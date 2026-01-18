# Deobfuscator.ps1
# Requires AstTool.ps1 to be sourced beforehand (for other scripts), but this script is self-contained for C# logic.

using namespace System.Management.Automation.Language
using namespace System.Collections.Generic

$csharpSource = @'
using System;
using System.IO;
using System.Text;
using System.Reflection;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Language;
using System.Text.RegularExpressions;

namespace DeobfuscatorInternal {

    // ========================================================================
    // Mutable AST Classes (Copied from AstToolKit to allow internal compilation)
    // ========================================================================
    
    public abstract class MutableAst {
        public string NodeType { get; set; }
        public MutableAst(string type) { NodeType = type; }
    }

    public class MutableStatementAst : MutableAst {
        public MutableStatementAst(string type) : base(type) {}
    }

    public class MutableStatementBlockAst : MutableStatementAst {
        public List<MutableStatementAst> Statements { get; set; } = new List<MutableStatementAst>();
        public MutableStatementBlockAst() : base("StatementBlockAst") {}
    }

    public class MutableScriptBlockAst : MutableAst {
        public MutableParamBlockAst ParamBlock { get; set; }
        public MutableStatementBlockAst BeginBlock { get; set; }
        public MutableStatementBlockAst ProcessBlock { get; set; }
        public MutableStatementBlockAst EndBlock { get; set; }
        public MutableStatementBlockAst DynamicParamBlock { get; set; }
        public bool IsFilter { get; set; }
        public bool IsConfiguration { get; set; }
        public MutableScriptBlockAst() : base("ScriptBlockAst") {}
    }

    public class MutableParamBlockAst : MutableAst {
        public List<MutableAttributeAst> Attributes { get; set; } = new List<MutableAttributeAst>();
        public List<MutableParameterAst> Parameters { get; set; } = new List<MutableParameterAst>();
        public MutableParamBlockAst() : base("ParamBlockAst") {}
    }

    public class MutableExpressionAst : MutableStatementAst {
        public MutableExpressionAst(string type) : base(type) {}
    }

    public class MutableParameterAst : MutableAst {
        public List<MutableAttributeAst> Attributes { get; set; } = new List<MutableAttributeAst>();
        public MutableVariableExpressionAst Name { get; set; }
        public MutableExpressionAst DefaultValue { get; set; }
        public MutableParameterAst() : base("ParameterAst") {}
    }

    public class MutableAttributeAst : MutableAst {
        public string TypeName { get; set; }
        public List<MutableExpressionAst> PositionalArguments { get; set; } = new List<MutableExpressionAst>();
        public Dictionary<string, MutableExpressionAst> NamedArguments { get; set; } = new Dictionary<string, MutableExpressionAst>();
        public MutableAttributeAst() : base("AttributeAst") {}
    }

    // --- Expressions ---

    public class MutableConstantExpressionAst : MutableExpressionAst {
        public object Value { get; set; }
        public MutableConstantExpressionAst() : base("ConstantExpressionAst") {}
    }

    public class MutableStringConstantExpressionAst : MutableExpressionAst {
        public string Value { get; set; }
        public StringConstantType StringConstantType { get; set; }
        public MutableStringConstantExpressionAst() : base("StringConstantExpressionAst") {}
    }

    public class MutableExpandableStringExpressionAst : MutableExpressionAst {
        public string Value { get; set; }
        public StringConstantType StringConstantType { get; set; }
        public MutableExpandableStringExpressionAst() : base("ExpandableStringExpressionAst") {}
    }

    public class MutableVariableExpressionAst : MutableExpressionAst {
        public string VariablePath { get; set; }
        public bool Splatted { get; set; }
        public MutableVariableExpressionAst() : base("VariableExpressionAst") {}
    }

    public class MutableBinaryExpressionAst : MutableExpressionAst {
        public MutableExpressionAst Left { get; set; }
        public TokenKind Operator { get; set; }
        public MutableExpressionAst Right { get; set; }
        public MutableBinaryExpressionAst() : base("BinaryExpressionAst") {}
    }

    public class MutableMemberExpressionAst : MutableExpressionAst {
        public MutableExpressionAst Expression { get; set; }
        public MutableExpressionAst Member { get; set; }
        public bool Static { get; set; }
        public MutableMemberExpressionAst() : base("MemberExpressionAst") {}
    }

    public class MutableInvokeMemberExpressionAst : MutableExpressionAst {
        public MutableExpressionAst Expression { get; set; }
        public MutableExpressionAst Member { get; set; }
        public List<MutableExpressionAst> Arguments { get; set; } = new List<MutableExpressionAst>();
        public bool Static { get; set; }
        public MutableInvokeMemberExpressionAst() : base("InvokeMemberExpressionAst") {}
    }

    public class MutableIndexExpressionAst : MutableExpressionAst {
        public MutableExpressionAst Target { get; set; }
        public MutableExpressionAst Index { get; set; }
        public MutableIndexExpressionAst() : base("IndexExpressionAst") {}
    }

    public class MutableArrayExpressionAst : MutableExpressionAst {
        public MutableStatementBlockAst SubExpression { get; set; }
        public MutableArrayExpressionAst() : base("ArrayExpressionAst") {}
    }

    public class MutableScriptBlockExpressionAst : MutableExpressionAst {
        public MutableScriptBlockAst ScriptBlock { get; set; }
        public MutableScriptBlockExpressionAst() : base("ScriptBlockExpressionAst") {}
    }

    public class MutableTypeExpressionAst : MutableExpressionAst {
        public string TypeName { get; set; }
        public MutableTypeExpressionAst() : base("TypeExpressionAst") {}
    }

    public class MutableParenExpressionAst : MutableExpressionAst {
        public MutableStatementAst Pipeline { get; set; }
        public MutableParenExpressionAst() : base("ParenExpressionAst") {}
    }

    public class MutableArrayLiteralAst : MutableExpressionAst {
        public List<MutableExpressionAst> Elements { get; set; } = new List<MutableExpressionAst>();
        public MutableArrayLiteralAst() : base("ArrayLiteralAst") {}
    }

    public class MutableConvertExpressionAst : MutableExpressionAst {
        public MutableAttributeAst Type { get; set; }
        public MutableExpressionAst Child { get; set; }
        public MutableConvertExpressionAst() : base("ConvertExpressionAst") {}
    }

    public class MutableAttributedExpressionAst : MutableExpressionAst {
        public MutableAttributeAst Attribute { get; set; }
        public MutableExpressionAst Child { get; set; }
        public MutableAttributedExpressionAst() : base("AttributedExpressionAst") {}
    }

    public class MutableSubExpressionAst : MutableExpressionAst {
        public MutableStatementBlockAst SubExpression { get; set; }
        public MutableSubExpressionAst() : base("SubExpressionAst") {}
    }

    public class MutableUsingExpressionAst : MutableExpressionAst {
        public MutableExpressionAst SubExpression { get; set; }
        public MutableUsingExpressionAst() : base("UsingExpressionAst") {}
    }

    public class MutableHashtableAst : MutableExpressionAst {
        public List<Tuple<MutableExpressionAst, MutableStatementAst>> KeyValuePairs { get; set; } 
            = new List<Tuple<MutableExpressionAst, MutableStatementAst>>();
        public MutableHashtableAst() : base("HashtableAst") {}
    }

    // --- Statements ---

    public class MutableAssignmentStatementAst : MutableStatementAst {
        public MutableExpressionAst Left { get; set; }
        public TokenKind Operator { get; set; }
        public MutableStatementAst Right { get; set; }
        public MutableAssignmentStatementAst() : base("AssignmentStatementAst") {}
    }

    public class MutableReturnStatementAst : MutableStatementAst {
        public MutableStatementAst Pipeline { get; set; }
        public MutableReturnStatementAst() : base("ReturnStatementAst") {}
    }

    public class MutablePipelineChainAst : MutableStatementAst {
        public MutableStatementAst Left { get; set; }
        public TokenKind Operator { get; set; }
        public MutableStatementAst Right { get; set; }
        public MutablePipelineChainAst() : base("PipelineChainAst") {}
    }

    public class MutableIfClause : MutableAst {
        public MutableStatementAst Item1 { get; set; } // Test
        public MutableStatementAst Item2 { get; set; } // Body
        public MutableIfClause() : base("IfClause") {}
    }

    public class MutableIfStatementAst : MutableStatementAst {
        public List<MutableIfClause> Clauses { get; set; } = new List<MutableIfClause>();
        public MutableStatementBlockAst ElseClause { get; set; }
        public MutableIfStatementAst() : base("IfStatementAst") {}
    }

    public class MutableTryStatementAst : MutableStatementAst {
        public MutableStatementBlockAst Body { get; set; }
        public List<MutableCatchClauseAst> CatchClauses { get; set; } = new List<MutableCatchClauseAst>();
        public MutableStatementBlockAst Finally { get; set; }
        public MutableTryStatementAst() : base("TryStatementAst") {}
    }

    public class MutableCatchClauseAst : MutableAst {
        public List<MutableTypeConstraintAst> CatchTypes { get; set; } = new List<MutableTypeConstraintAst>();
        public MutableStatementBlockAst Body { get; set; }
        public MutableCatchClauseAst() : base("CatchClauseAst") {}
    }

    public class MutableTypeConstraintAst : MutableAttributeAst {
        public MutableTypeConstraintAst() : base() { NodeType = "TypeConstraintAst"; }
    }

    public class MutableTrapStatementAst : MutableStatementAst {
        public MutableTypeConstraintAst TrapType { get; set; }
        public MutableStatementBlockAst Body { get; set; }
        public MutableTrapStatementAst() : base("TrapStatementAst") {}
    }

    public class MutableDataStatementAst : MutableStatementAst {
        public string Variable { get; set; }
        public List<MutableExpressionAst> CommandsAllowed { get; set; } = new List<MutableExpressionAst>();
        public MutableStatementBlockAst Body { get; set; }
        public MutableDataStatementAst() : base("DataStatementAst") {}
    }

    public abstract class MutableCommandBaseAst : MutableStatementAst {
        public List<MutableRedirectionAst> Redirections { get; set; } = new List<MutableRedirectionAst>();
        public MutableCommandBaseAst(string type) : base(type) {}
    }

    public class MutableCommandAst : MutableCommandBaseAst {
        public List<MutableAst> CommandElements { get; set; } = new List<MutableAst>();
        public object InvocationOperator { get; set; }
        public MutableCommandAst() : base("CommandAst") {}
    }

    public class MutableCommandExpressionAst : MutableCommandBaseAst {
        public MutableExpressionAst Expression { get; set; }
        public MutableCommandExpressionAst() : base("CommandExpressionAst") {}
    }

    public class MutableCommandParameterAst : MutableExpressionAst {
        public string ParameterName { get; set; }
        public MutableExpressionAst Argument { get; set; }
        public MutableCommandParameterAst() : base("CommandParameterAst") {}
    }

    public abstract class MutableRedirectionAst : MutableAst {
        public RedirectionStream From { get; set; }
        public MutableRedirectionAst(string type) : base(type) {}
    }

    public class MutableFileRedirectionAst : MutableRedirectionAst {
        public MutableExpressionAst Location { get; set; }
        public bool Append { get; set; }
        public MutableFileRedirectionAst() : base("FileRedirectionAst") {}
    }

    public class MutableMergingRedirectionAst : MutableRedirectionAst {
        public RedirectionStream To { get; set; }
        public MutableMergingRedirectionAst() : base("MergingRedirectionAst") {}
    }

    public class MutablePipelineAst : MutableStatementAst {
        public List<MutableCommandBaseAst> PipelineElements { get; set; } = new List<MutableCommandBaseAst>();
        public MutablePipelineAst() : base("PipelineAst") {}
    }

    public class MutableBlockStatementAst : MutableStatementAst {
        public MutableStatementBlockAst Body { get; set; }
        public MutableBlockStatementAst() : base("BlockStatementAst") {}
    }

    public class MutableErrorStatementAst : MutableStatementAst {
        public string ErrorMessage { get; set; }
        public string OriginalText { get; set; }
        public List<MutableAst> NestedAst { get; set; } = new List<MutableAst>();
        public MutableErrorStatementAst() : base("ErrorStatementAst") {}
    }

    public class MutableErrorExpressionAst : MutableExpressionAst {
        public string ErrorMessage { get; set; }
        public string OriginalText { get; set; }
        public List<MutableAst> NestedAst { get; set; } = new List<MutableAst>();
        public MutableErrorExpressionAst() : base("ErrorExpressionAst") {}
    }

    public class MutableFunctionDefinitionAst : MutableStatementAst {
        public string Name { get; set; }
        public MutableScriptBlockAst Body { get; set; }
        public List<MutableParameterAst> Parameters { get; set; } = new List<MutableParameterAst>();
        public bool IsFilter { get; set; }
        public bool IsWorkflow { get; set; }
        public MutableFunctionDefinitionAst() : base("FunctionDefinitionAst") {}
    }

    public class MutableExitStatementAst : MutableStatementAst {
        public MutableStatementAst Pipeline { get; set; }
        public MutableExitStatementAst() : base("ExitStatementAst") {}
    }

    public class MutableThrowStatementAst : MutableStatementAst {
        public MutableStatementAst Pipeline { get; set; }
        public MutableThrowStatementAst() : base("ThrowStatementAst") {}
    }

    public class MutableBreakStatementAst : MutableStatementAst {
        public MutableExpressionAst Label { get; set; }
        public MutableBreakStatementAst() : base("BreakStatementAst") {}
    }

    public class MutableContinueStatementAst : MutableStatementAst {
        public MutableExpressionAst Label { get; set; }
        public MutableContinueStatementAst() : base("ContinueStatementAst") {}
    }

    public class MutableWhileStatementAst : MutableStatementAst {
        public MutableStatementAst Condition { get; set; }
        public MutableStatementBlockAst Body { get; set; }
        public MutableWhileStatementAst() : base("WhileStatementAst") {}
    }

    public class MutableDoWhileStatementAst : MutableStatementAst {
        public MutableStatementAst Condition { get; set; }
        public MutableStatementBlockAst Body { get; set; }
        public MutableDoWhileStatementAst() : base("DoWhileStatementAst") {}
    }

    public class MutableDoUntilStatementAst : MutableStatementAst {
        public MutableStatementAst Condition { get; set; }
        public MutableStatementBlockAst Body { get; set; }
        public MutableDoUntilStatementAst() : base("DoUntilStatementAst") {}
    }

    public class MutableForStatementAst : MutableStatementAst {
        public MutableStatementAst Initializer { get; set; }
        public MutableStatementAst Condition { get; set; }
        public MutableStatementAst Iterator { get; set; }
        public MutableStatementBlockAst Body { get; set; }
        public MutableForStatementAst() : base("ForStatementAst") {}
    }

    public class MutableForEachStatementAst : MutableStatementAst {
        public MutableVariableExpressionAst Variable { get; set; }
        public MutableStatementAst Condition { get; set; }
        public MutableStatementBlockAst Body { get; set; }
        public ForEachFlags Flags { get; set; }
        public MutableForEachStatementAst() : base("ForEachStatementAst") {}
    }

    public class MutableUnaryExpressionAst : MutableExpressionAst {
        public TokenKind TokenKind { get; set; }
        public MutableExpressionAst Child { get; set; }
        public MutableUnaryExpressionAst() : base("UnaryExpressionAst") {}
    }

    public class MutableSwitchStatementAst : MutableStatementAst {
        public string Label { get; set; }
        public MutableStatementAst Condition { get; set; }
        public SwitchFlags Flags { get; set; }
        public List<MutableIfClause> Clauses { get; set; } = new List<MutableIfClause>();
        public MutableStatementBlockAst Default { get; set; }
        public MutableSwitchStatementAst() : base("SwitchStatementAst") {}
    }
    
    // --- Type Definitions ---
    public abstract class MutableMemberAst : MutableAst {
        public string Name { get; set; }
        public MutableMemberAst(string type) : base(type) {}
    }
    
    public class MutablePropertyMemberAst : MutableMemberAst {
        public List<MutableAttributeAst> Attributes { get; set; } = new List<MutableAttributeAst>();
        public MutableTypeConstraintAst PropertyType { get; set; }
        public MutableExpressionAst InitialValue { get; set; }
        public bool Static { get; set; }
        public int PropertyAttributes { get; set; }
        public MutablePropertyMemberAst() : base("PropertyMemberAst") {}
    }

    public class MutableFunctionMemberAst : MutableMemberAst {
        public List<MutableAttributeAst> Attributes { get; set; } = new List<MutableAttributeAst>();
        public MutableTypeConstraintAst ReturnType { get; set; }
        public List<MutableParameterAst> Parameters { get; set; } = new List<MutableParameterAst>();
        public MutableScriptBlockAst Body { get; set; }
        public bool Static { get; set; }
        public int MethodAttributes { get; set; }
        public MutableFunctionMemberAst() : base("FunctionMemberAst") {}
    }

    public class MutableTypeDefinitionAst : MutableStatementAst {
        public string Name { get; set; }
        public List<MutableAttributeAst> Attributes { get; set; } = new List<MutableAttributeAst>();
        public List<MutableTypeConstraintAst> BaseTypes { get; set; } = new List<MutableTypeConstraintAst>();
        public List<MutableMemberAst> Members { get; set; } = new List<MutableMemberAst>();
        public int TypeAttributes { get; set; }
        public bool IsEnum { get; set; }
        public bool IsClass { get; set; }
        public bool IsInterface { get; set; }
        public MutableTypeDefinitionAst() : base("TypeDefinitionAst") {}
    }

    // ========================================================================
    // Converter
    // ========================================================================
    
    public static class MutableAstConverter {
    
        public static MutableAst Convert(Ast node) {
            if (node == null) return null;
            
            if (node is ScriptBlockAst sb) {
                var m = new MutableScriptBlockAst();
                m.ParamBlock = (MutableParamBlockAst)Convert(sb.ParamBlock);
                m.BeginBlock = (MutableStatementBlockAst)Convert(sb.BeginBlock);
                m.ProcessBlock = (MutableStatementBlockAst)Convert(sb.ProcessBlock);
                m.EndBlock = (MutableStatementBlockAst)Convert(sb.EndBlock);
                m.DynamicParamBlock = (MutableStatementBlockAst)Convert(sb.DynamicParamBlock);
                return m;
            }
            if (node is ParamBlockAst pb) {
                var m = new MutableParamBlockAst();
                foreach(var paramAttr in pb.Attributes) m.Attributes.Add((MutableAttributeAst)Convert(paramAttr));
                foreach(var paramNode in pb.Parameters) m.Parameters.Add((MutableParameterAst)Convert(paramNode));
                return m;
            }
            if (node is ParameterAst p) {
                var m = new MutableParameterAst();
                m.Name = (MutableVariableExpressionAst)Convert(p.Name);
                m.DefaultValue = (MutableExpressionAst)Convert(p.DefaultValue);
                foreach(var a in p.Attributes) m.Attributes.Add((MutableAttributeAst)Convert(a));
                return m;
            }
            if (node is TypeConstraintAst tc) {
                var m = new MutableTypeConstraintAst();
                m.TypeName = tc.TypeName.FullName;
                return m;
            }
            if (node is AttributeAst attr) {
                var m = new MutableAttributeAst();
                m.TypeName = attr.TypeName.FullName;
                foreach(var arg in attr.PositionalArguments) m.PositionalArguments.Add((MutableExpressionAst)Convert(arg));
                foreach(var pair in attr.NamedArguments) m.NamedArguments[pair.ArgumentName] = (MutableExpressionAst)Convert(pair.Argument);
                return m;
            }
            if (node is AssignmentStatementAst assign) {
                var m = new MutableAssignmentStatementAst();
                m.Left = (MutableExpressionAst)Convert(assign.Left);
                m.Operator = assign.Operator;
                m.Right = (MutableStatementAst)Convert(assign.Right);
                return m;
            }
            if (node is TrapStatementAst trap) {
                var m = new MutableTrapStatementAst();
                m.TrapType = (MutableTypeConstraintAst)Convert(trap.TrapType);
                m.Body = (MutableStatementBlockAst)Convert(trap.Body);
                return m;
            }
            if (node is DataStatementAst data) {
                var m = new MutableDataStatementAst();
                m.Variable = data.Variable;
                if (data.CommandsAllowed != null) {
                    foreach (var c in data.CommandsAllowed) m.CommandsAllowed.Add((MutableExpressionAst)Convert(c));
                }
                m.Body = (MutableStatementBlockAst)Convert(data.Body);
                return m;
            }
            if (node is PipelineAst pipe) {
                var m = new MutablePipelineAst();
                foreach(var e in pipe.PipelineElements) m.PipelineElements.Add((MutableCommandBaseAst)Convert(e));
                return m;
            }
            if (node is CommandAst cmd) {
                var m = new MutableCommandAst();
                m.InvocationOperator = cmd.InvocationOperator;
                foreach(var e in cmd.CommandElements) m.CommandElements.Add(Convert(e));
                foreach(var r in cmd.Redirections) m.Redirections.Add((MutableRedirectionAst)Convert(r));
                return m;
            }
            if (node is CommandExpressionAst ce) {
                var m = new MutableCommandExpressionAst();
                m.Expression = (MutableExpressionAst)Convert(ce.Expression);
                foreach(var r in ce.Redirections) m.Redirections.Add((MutableRedirectionAst)Convert(r));
                return m;
            }
            if (node is CommandParameterAst cp) {
                var m = new MutableCommandParameterAst();
                m.ParameterName = cp.ParameterName;
                m.Argument = (MutableExpressionAst)Convert(cp.Argument);
                return m;
            }
            if (node is FileRedirectionAst fr) {
                var m = new MutableFileRedirectionAst();
                m.From = fr.FromStream;
                m.Location = (MutableExpressionAst)Convert(fr.Location);
                m.Append = fr.Append;
                return m;
            }
            if (node is MergingRedirectionAst mr) {
                var m = new MutableMergingRedirectionAst();
                m.From = mr.FromStream;
                m.To = mr.ToStream;
                return m;
            }
            if (node is StringConstantExpressionAst sce) {
                var m = new MutableStringConstantExpressionAst();
                m.Value = sce.Value;
                m.StringConstantType = sce.StringConstantType;
                return m;
            }
            if (node is ConstantExpressionAst constExpr) {
                var m = new MutableConstantExpressionAst();
                m.Value = constExpr.Value;
                return m;
            }
            if (node is VariableExpressionAst ve) {
                var m = new MutableVariableExpressionAst();
                
                string raw = ve.VariablePath.UserPath;
                // Try to recover original source to handle platform-specific parsing (e.g. `e on PS Core)
                if (ve.Extent != null) {
                    string text = ve.Extent.Text;
                    var match = Regex.Match(text, @"^\$\s*\{(.*)\}$", RegexOptions.Singleline);
                    if (match.Success) {
                        raw = match.Groups[1].Value;
                    }
                }

                // Aggressively remove backticks and spaces to normalize obfuscated names
                m.VariablePath = raw.Replace("`", "").Replace(" ", "").Replace("\u0060", "").Replace("\u001b", "");
                m.Splatted = ve.Splatted;
                return m;
            }
            if (node is ExpandableStringExpressionAst ese) {
                var m = new MutableExpandableStringExpressionAst();
                m.Value = ese.Value;
                m.StringConstantType = ese.StringConstantType;
                return m;
            }
            if (node is BinaryExpressionAst bin) {
                var m = new MutableBinaryExpressionAst();
                m.Left = (MutableExpressionAst)Convert(bin.Left);
                m.Operator = bin.Operator;
                m.Right = (MutableExpressionAst)Convert(bin.Right);
                return m;
            }
            if (node is InvokeMemberExpressionAst ime) {
                var m = new MutableInvokeMemberExpressionAst();
                m.Expression = (MutableExpressionAst)Convert(ime.Expression);
                m.Member = (MutableExpressionAst)Convert(ime.Member);
                m.Static = ime.Static;
                if (ime.Arguments != null) {
                    foreach(var arg in ime.Arguments) m.Arguments.Add((MutableExpressionAst)Convert(arg));
                }
                return m;
            }
            if (node is MemberExpressionAst me) {
                var m = new MutableMemberExpressionAst();
                m.Expression = (MutableExpressionAst)Convert(me.Expression);
                m.Member = (MutableExpressionAst)Convert(me.Member);
                m.Static = me.Static;
                return m;
            }
            if (node is IndexExpressionAst ie) {
                var m = new MutableIndexExpressionAst();
                m.Target = (MutableExpressionAst)Convert(ie.Target);
                m.Index = (MutableExpressionAst)Convert(ie.Index);
                return m;
            }
            if (node is ArrayExpressionAst ae) {
                var m = new MutableArrayExpressionAst();
                m.SubExpression = (MutableStatementBlockAst)Convert(ae.SubExpression);
                return m;
            }
            if (node is ParenExpressionAst paren) {
                var m = new MutableParenExpressionAst();
                m.Pipeline = (MutableStatementAst)Convert(paren.Pipeline);
                return m;
            }
            if (node is IfStatementAst ifStmt) {
                var m = new MutableIfStatementAst();
                foreach(var c in ifStmt.Clauses) {
                    var mc = new MutableIfClause();
                    mc.Item1 = (MutableStatementAst)Convert(c.Item1);
                    mc.Item2 = (MutableStatementAst)Convert(c.Item2);
                    m.Clauses.Add(mc);
                }
                m.ElseClause = (MutableStatementBlockAst)Convert(ifStmt.ElseClause);
                return m;
            }
            if (node is ForEachStatementAst fe) {
                var m = new MutableForEachStatementAst();
                m.Variable = (MutableVariableExpressionAst)Convert(fe.Variable);
                m.Condition = (MutableStatementAst)Convert(fe.Condition);
                m.Body = (MutableStatementBlockAst)Convert(fe.Body);
                m.Flags = fe.Flags;
                return m;
            }
            if (node is ForStatementAst fs) {
                var m = new MutableForStatementAst();
                m.Initializer = (MutableStatementAst)Convert(fs.Initializer);
                m.Condition = (MutableStatementAst)Convert(fs.Condition);
                m.Iterator = (MutableStatementAst)Convert(fs.Iterator);
                m.Body = (MutableStatementBlockAst)Convert(fs.Body);
                return m;
            }
            if (node is WhileStatementAst ws) {
                var m = new MutableWhileStatementAst();
                m.Condition = (MutableStatementAst)Convert(ws.Condition);
                m.Body = (MutableStatementBlockAst)Convert(ws.Body);
                return m;
            }
            if (node is DoWhileStatementAst dws) {
                var m = new MutableDoWhileStatementAst();
                m.Condition = (MutableStatementAst)Convert(dws.Condition);
                m.Body = (MutableStatementBlockAst)Convert(dws.Body);
                return m;
            }
            if (node is DoUntilStatementAst dus) {
                var m = new MutableDoUntilStatementAst();
                m.Condition = (MutableStatementAst)Convert(dus.Condition);
                m.Body = (MutableStatementBlockAst)Convert(dus.Body);
                return m;
            }
            if (node is SwitchStatementAst sw) {
                var m = new MutableSwitchStatementAst();
                m.Label = sw.Label; // Corrected: Label is string, not expression
                m.Condition = (MutableStatementAst)Convert(sw.Condition);
                m.Flags = sw.Flags;
                m.Default = (MutableStatementBlockAst)Convert(sw.Default);
                foreach(var c in sw.Clauses) {
                    var mc = new MutableIfClause();
                    mc.Item1 = (MutableStatementAst)Convert(c.Item1);
                    mc.Item2 = (MutableStatementAst)Convert(c.Item2);
                    m.Clauses.Add(mc);
                }
                return m;
            }
            if (node is ReturnStatementAst ret) {
                var m = new MutableReturnStatementAst();
                m.Pipeline = (MutableStatementAst)Convert(ret.Pipeline);
                return m;
            }
            if (node is ExitStatementAst ex) {
                var m = new MutableExitStatementAst();
                m.Pipeline = (MutableStatementAst)Convert(ex.Pipeline);
                return m;
            }
            if (node is ThrowStatementAst th) {
                var m = new MutableThrowStatementAst();
                m.Pipeline = (MutableStatementAst)Convert(th.Pipeline);
                return m;
            }
            if (node is BreakStatementAst br) {
                var m = new MutableBreakStatementAst();
                m.Label = (MutableExpressionAst)Convert(br.Label);
                return m;
            }
            if (node is ContinueStatementAst cont) {
                var m = new MutableContinueStatementAst();
                m.Label = (MutableExpressionAst)Convert(cont.Label);
                return m;
            }
            if (node is BlockStatementAst blk) {
                var m = new MutableBlockStatementAst();
                m.Body = (MutableStatementBlockAst)Convert(blk.Body);
                return m;
            }
            if (node is StatementBlockAst sbAst) {
                var m = new MutableStatementBlockAst();
                foreach(var s in sbAst.Statements) m.Statements.Add((MutableStatementAst)Convert(s));
                return m;
            }
            if (node is NamedBlockAst nb) {
                // Treat as StatementBlock
                var m = new MutableStatementBlockAst();
                foreach(var s in nb.Statements) m.Statements.Add((MutableStatementAst)Convert(s));
                return m;
            }
            if (node is ScriptBlockExpressionAst sbe) {
                var m = new MutableScriptBlockExpressionAst();
                m.ScriptBlock = (MutableScriptBlockAst)Convert(sbe.ScriptBlock);
                return m;
            }
            if (node is TypeExpressionAst te) {
                var m = new MutableTypeExpressionAst();
                m.TypeName = te.TypeName.FullName;
                return m;
            }
            if (node is ArrayLiteralAst ala) {
                var m = new MutableArrayLiteralAst();
                foreach(var e in ala.Elements) m.Elements.Add((MutableExpressionAst)Convert(e));
                return m;
            }
            if (node is SubExpressionAst sub) {
                var m = new MutableSubExpressionAst();
                m.SubExpression = (MutableStatementBlockAst)Convert(sub.SubExpression);
                return m;
            }
            if (node is UsingExpressionAst use) {
                var m = new MutableUsingExpressionAst();
                m.SubExpression = (MutableExpressionAst)Convert(use.SubExpression);
                return m;
            }
            if (node is FunctionDefinitionAst fd) {
                var m = new MutableFunctionDefinitionAst();
                m.Name = fd.Name;
                m.IsFilter = fd.IsFilter;
                m.IsWorkflow = fd.IsWorkflow;
                m.Body = (MutableScriptBlockAst)Convert(fd.Body);
                if (fd.Parameters != null) {
                    foreach(var paramNode in fd.Parameters) m.Parameters.Add((MutableParameterAst)Convert(paramNode));
                }
                return m;
            }
            if (node is TryStatementAst tr) {
                var m = new MutableTryStatementAst();
                m.Body = (MutableStatementBlockAst)Convert(tr.Body);
                foreach(var c in tr.CatchClauses) m.CatchClauses.Add((MutableCatchClauseAst)Convert(c));
                m.Finally = (MutableStatementBlockAst)Convert(tr.Finally);
                return m;
            }
            if (node is CatchClauseAst cc) {
                var m = new MutableCatchClauseAst();
                foreach(var t in cc.CatchTypes) m.CatchTypes.Add((MutableTypeConstraintAst)Convert(t));
                m.Body = (MutableStatementBlockAst)Convert(cc.Body);
                return m;
            }
            if (node is HashtableAst ht) {
                var m = new MutableHashtableAst();
                foreach(var pair in ht.KeyValuePairs) {
                    m.KeyValuePairs.Add(new Tuple<MutableExpressionAst, MutableStatementAst>(
                        (MutableExpressionAst)Convert(pair.Item1),
                        (MutableStatementAst)Convert(pair.Item2)
                    ));
                }
                return m;
            }
            if (node is PipelineChainAst pc) {
                var m = new MutablePipelineChainAst();
                m.Left = (MutableStatementAst)Convert(pc.LhsPipelineChain); // Corrected property
                m.Operator = pc.Operator;
                m.Right = (MutableStatementAst)Convert(pc.RhsPipeline); // Corrected property
                return m;
            }
            if (node is UnaryExpressionAst u) {
                var m = new MutableUnaryExpressionAst();
                m.TokenKind = u.TokenKind;
                m.Child = (MutableExpressionAst)Convert(u.Child);
                return m;
            }
            if (node is ConvertExpressionAst ceAst) {
                var m = new MutableConvertExpressionAst();
                m.Type = (MutableAttributeAst)Convert(ceAst.Type);
                m.Child = (MutableExpressionAst)Convert(ceAst.Child);
                return m;
            }
            if (node is AttributedExpressionAst att) {
                var m = new MutableAttributedExpressionAst();
                m.Attribute = (MutableAttributeAst)Convert(att.Attribute);
                m.Child = (MutableExpressionAst)Convert(att.Child);
                return m;
            }
            if (node is TypeDefinitionAst td) {
                var m = new MutableTypeDefinitionAst();
                m.Name = td.Name;
                m.TypeAttributes = (int)td.TypeAttributes;
                m.IsEnum = td.IsEnum;
                m.IsClass = td.IsClass;
                m.IsInterface = td.IsInterface;
                foreach(var a in td.Attributes) m.Attributes.Add((MutableAttributeAst)Convert(a));
                foreach(var bt in td.BaseTypes) m.BaseTypes.Add((MutableTypeConstraintAst)Convert(bt));
                foreach(var member in td.Members) m.Members.Add((MutableMemberAst)Convert(member));
                return m;
            }
            if (node is PropertyMemberAst pm) {
                var m = new MutablePropertyMemberAst();
                m.Name = pm.Name;
                m.Static = pm.IsStatic;
                m.PropertyAttributes = (int)pm.PropertyAttributes;
                m.PropertyType = (MutableTypeConstraintAst)Convert(pm.PropertyType);
                m.InitialValue = (MutableExpressionAst)Convert(pm.InitialValue);
                foreach(var a in pm.Attributes) m.Attributes.Add((MutableAttributeAst)Convert(a));
                return m;
            }
            if (node is FunctionMemberAst fm) {
                var m = new MutableFunctionMemberAst();
                m.Name = fm.Name;
                m.Static = fm.IsStatic;
                m.MethodAttributes = (int)fm.MethodAttributes;
                m.ReturnType = (MutableTypeConstraintAst)Convert(fm.ReturnType);
                m.Body = (MutableScriptBlockAst)Convert(fm.Body);
                foreach(var a in fm.Attributes) m.Attributes.Add((MutableAttributeAst)Convert(a));
                foreach(var param in fm.Parameters) m.Parameters.Add((MutableParameterAst)Convert(param));
                return m;
            }
            if (node is ErrorStatementAst es) {
                 var m = new MutableErrorStatementAst();
                 m.ErrorMessage = null;
                 m.OriginalText = es.Extent.Text;
                 if (es.NestedAst != null) {
                     foreach(var n in es.NestedAst) m.NestedAst.Add(Convert(n));
                 }
                 return m;
            }
            if (node is ErrorExpressionAst ee) {
                 var m = new MutableErrorExpressionAst();
                 m.ErrorMessage = null;
                 m.OriginalText = ee.Extent.Text;
                 if (ee.NestedAst != null) {
                     foreach(var n in ee.NestedAst) m.NestedAst.Add(Convert(n));
                 }
                 return m;
            }

            // Fallback
            var err = new MutableErrorExpressionAst();
            err.ErrorMessage = "Unknown Node Type: " + node.GetType().Name;
            return err;
        }
    }

    // ========================================================================
    // Generator
    // ========================================================================

        public static class TokenKindHelper {

            public static string GetTokenString(object kindObj) {

                if (kindObj == null) return "";

                string kind = kindObj.ToString().ToLowerInvariant();

    

                switch (kind) {

                    case "equals": return "=";

                    case "plus": return "+";

                    case "minus": return "-";

                    case "multiply": return "*";

                    case "divide": return "/";

                    case "rem": return "%" ;

                    case "and": return "-and";

                    case "or": return "-or";

                    case "xor": return "-xor";

                    case "not": return "-not";

                    case "band": return "-band";

                    case "bor": return "-bor";

                    case "bxor": return "-bxor";

                    case "bnot": return "-bnot";

                    case "ampersand": return "&";

                    case "pipe": return "|";

                    case "comma": return ",";

                    case "dot": return ".";

                    case "colon": return ":";

                    case "semi": return ";";

                    case "lparen": return "(";

                    case "rparen": return ")";

                    case "lbracket": return "[";

                    case "rbracket": return "]";

                    case "lcurly": return "{";

                    case "rcurly": return "}";

                    case "iin": return "-in";

                    case "inotin": return "-notin";

                    case "ieq": return "-eq";

                    case "ine": return "-ne";

                    case "ige": return "-ge";

                    case "igt": return "-gt";

                    case "ile": return "-le";

                    case "ilt": return "-lt";

                    case "imatch": return "-match";

                    case "inotmatch": return "-notmatch";

                    case "ilike": return "-like";

                    case "inotlike": return "-notlike";

                    case "icontains": return "-contains";

                    case "inotcontains": return "-notcontains";

                    case "is": return "-is";

                    case "isnot": return "-isnot";

                    case "as": return "-as";

                    case "dotdot": return "..";

                    case "splattedvariable": return "@";

                    case "variable": return "$";

                    case "join": return "-join";

                    case "isplit": return "-split";

                    case "csplit": return "-csplit";

                    case "ceq": return "-ceq";

                    case "cne": return "-cne";

                    case "cge": return "-cge";

                    case "cgt": return "-cgt";

                    case "cle": return "-cle";

                    case "clt": return "-clt";

                    case "cmatch": return "-cmatch";

                    case "cnotmatch": return "-cnotmatch";

                    case "clike": return "-clike";

                    case "cnotlike": return "-cnotlike";

                    case "ccontains": return "-ccontains";

                    case "cnotcontains": return "-cnotcontains";

                    case "cin": return "-cin";

                    case "cnotin": return "-cnotin";

                    case "replace": return "-replace";

                    case "ireplace": return "-ireplace";

                    case "creplace": return "-creplace";

                    case "shl": return "-shl";

                    case "shr": return "-shr";

                    case "exclaim": return "!";

                    case "questionmark": return "?";

                    case "questionquestion": return "??";

                    case "questionquestionequals": return "??=";

                    case "questiondot": return "?. ";

                case "format": return "-f";
                case "postfixplusplus": return "++";

                    case "postfixminusminus": return "--";

                    case "plusplus": return "++";

                    case "minusminus": return "--";

                                    case "preplusplus": return "++";

                                    case "preminusminus": return "--";

                                    case "plusequals": return "+=";

                                    case "minusequals": return "-=";

                                    case "multiplyequals": return "*=";

                                    case "divideequals": return "/=";

                                    case "remainderequals": return "%=";

                                    default: return kindObj.ToString(); // Return original if no match

                                }

            }

        }

    public static class AstSourceCodeGenerator {

        public static string ConvertToSourceCode(object node) {
            if (node == null) return "";
            StringBuilder sb = new StringBuilder(65536);
            WriteAstNode(node, 0, sb);
            return sb.ToString();
        }

        private static ConcurrentDictionary<string, PropertyInfo> _propertyCache = new ConcurrentDictionary<string, PropertyInfo>();

        // Helper to get property from either Native AST or Mutable AST
        private static object GetProperty(object obj, string propName) {
            if (obj == null) return null;
            var type = obj.GetType();
            string cacheKey = type.FullName + "." + propName;

            if (_propertyCache.TryGetValue(cacheKey, out PropertyInfo cachedProp)) {
                return cachedProp?.GetValue(obj);
            }

            PropertyInfo prop = null;

            // For tuples
            if ((propName == "Item1" || propName == "Item2") && type.Name.StartsWith("Tuple")) {
                 prop = type.GetProperty(propName);
            }
            else {
                try {
                    // Try standard GetProperty first (might throw AmbiguousMatchException)
                    prop = type.GetProperty(propName);
                }
                catch (AmbiguousMatchException) {
                    // Handle ambiguity: Prefer the property declared on the most derived type
                    prop = type.GetProperty(propName, BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);
                    
                    if (prop == null) {
                        // Fallback: look up the hierarchy if not found on the immediate type
                        var baseType = type.BaseType;
                        while (baseType != null) {
                            prop = baseType.GetProperty(propName, BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);
                            if (prop != null) break;
                            baseType = baseType.BaseType;
                        }
                    }
                }
            }

            _propertyCache[cacheKey] = prop;

            if (prop != null) return prop.GetValue(obj);
            return null;
        }

        private static void WriteAstNode(object node, int indentLevel, StringBuilder sb) {
            if (node == null) return;

            string indentStr = new string(' ', indentLevel * 4);
            string typeName = node.GetType().Name;

            // ScriptBlockAst
            if (typeName == "ScriptBlockAst" || typeName == "MutableScriptBlockAst") {
                var paramBlock = GetProperty(node, "ParamBlock");
                if (paramBlock != null) {
                    WriteAstNode(paramBlock, indentLevel, sb);
                }

                var beginBlock = GetProperty(node, "BeginBlock");
                var processBlock = GetProperty(node, "ProcessBlock");
                var endBlock = GetProperty(node, "EndBlock");
                var dynamicParamBlock = GetProperty(node, "DynamicParamBlock");

                bool hasNamedBlocks = (beginBlock != null) || (processBlock != null) || (dynamicParamBlock != null);

                if (dynamicParamBlock != null) {
                     sb.Append(indentStr).Append("dynamicparam {\n");
                     WriteAstNode(dynamicParamBlock, indentLevel + 1, sb);
                     sb.Append(indentStr).Append("}\n");
                }
                if (beginBlock != null) {
                     sb.Append(indentStr).Append("begin {\n");
                     WriteAstNode(beginBlock, indentLevel + 1, sb);
                     sb.Append(indentStr).Append("}\n");
                }
                if (processBlock != null) {
                     sb.Append(indentStr).Append("process {\n");
                     WriteAstNode(processBlock, indentLevel + 1, sb);
                     sb.Append(indentStr).Append("}\n");
                }
                if (endBlock != null) {
                     if (hasNamedBlocks) {
                        sb.Append(indentStr).Append("end {\n");
                        WriteAstNode(endBlock, indentLevel + 1, sb);
                        sb.Append(indentStr).Append("}\n");
                     } else {
                        // Simple script block (only EndBlock, no keywords)
                        WriteAstNode(endBlock, indentLevel, sb);
                     }
                }
            }

            // ParamBlockAst
            else if (typeName == "ParamBlockAst" || typeName == "MutableParamBlockAst") {
                var attributes = GetProperty(node, "Attributes") as IEnumerable;
                if (attributes != null) {
                    foreach (var attr in attributes) {
                        sb.Append(indentStr);
                        WriteAstNode(attr, 0, sb);
                        sb.Append("\n");
                    }
                }
                sb.Append(indentStr).Append("param(");
                var parameters = GetProperty(node, "Parameters") as IEnumerable;
                if (parameters != null) {
                    var list = new List<object>();
                    foreach (var p in parameters) list.Add(p);

                    for (int i = 0; i < list.Count; i++) {
                        WriteAstNode(list[i], 0, sb);
                        if (i < list.Count - 1) sb.Append(", ");
                    }
                }
                sb.Append(")\n");
            }

            // ParameterAst
            else if (typeName == "ParameterAst" || typeName == "MutableParameterAst") {
                var attributes = GetProperty(node, "Attributes") as IEnumerable;
                if (attributes != null) {
                    foreach (var attr in attributes) {
                        WriteAstNode(attr, 0, sb);
                        sb.Append(" ");
                    }
                }
                WriteAstNode(GetProperty(node, "Name"), 0, sb);
                var defaultValue = GetProperty(node, "DefaultValue");
                if (defaultValue != null) {
                    sb.Append(" = ");
                    WriteAstNode(defaultValue, 0, sb);
                }
            }

            // AttributeAst / TypeConstraintAst
            else if (typeName == "AttributeAst" || typeName == "TypeConstraintAst" ||
                     typeName == "MutableAttributeAst" || typeName == "MutableTypeConstraintAst") {
                
                string t = "";
                // Native has TypeName property which is ITypeName, Mutable has string
                var typeNameObj = GetProperty(node, "TypeName");
                if (typeNameObj != null) {
                     var fullName = GetProperty(typeNameObj, "FullName");
                     t = fullName != null ? fullName.ToString() : typeNameObj.ToString();
                }
                sb.Append("[").Append(t);

                // Add arguments for AttributeAst (TypeConstraintAst typically doesn't have them)
                if (typeName.Contains("AttributeAst")) {
                    var posArgs = GetProperty(node, "PositionalArguments") as IEnumerable;
                    var namedArgsObj = GetProperty(node, "NamedArguments");

                    bool hasPos = false;
                    if (posArgs != null) {
                        foreach (var arg in posArgs) { hasPos = true; break; }
                    }
                    
                    bool hasNamed = false;
                    IDictionary namedArgsDict = namedArgsObj as IDictionary;
                    IEnumerable namedArgsEnum = namedArgsObj as IEnumerable;
                    
                    if (namedArgsDict != null) {
                         if (namedArgsDict.Count > 0) hasNamed = true;
                    } else if (namedArgsEnum != null) {
                         foreach (var item in namedArgsEnum) { hasNamed = true; break; }
                    }

                    if (hasPos || hasNamed) {
                        sb.Append("(");
                        bool first = true;
                        if (posArgs != null) {
                            foreach (var arg in posArgs) {
                                if (!first) sb.Append(", ");
                                WriteAstNode(arg, 0, sb);
                                first = false;
                            }
                        }
                        
                        if (namedArgsDict != null) {
                            foreach (DictionaryEntry entry in namedArgsDict) {
                                if (!first) sb.Append(", ");
                                sb.Append(entry.Key).Append(" = ");
                                WriteAstNode(entry.Value, 0, sb);
                                first = false;
                            }
                        } else if (namedArgsEnum != null) {
                             // Native AST: ReadOnlyCollection<NamedAttributeArgumentAst>
                             foreach (var item in namedArgsEnum) {
                                  if (!first) sb.Append(", ");
                                  var name = GetProperty(item, "ArgumentName");
                                  var arg = GetProperty(item, "Argument");
                                  sb.Append(name).Append(" = ");
                                  WriteAstNode(arg, 0, sb);
                                  first = false;
                             }
                        }
                        
                        sb.Append(")");
                    }
                }
                
                sb.Append("]");
            }

            // AssignmentStatementAst
            else if (typeName == "AssignmentStatementAst" || typeName == "MutableAssignmentStatementAst") {
                sb.Append(indentStr);
                WriteAstNode(GetProperty(node, "Left"), 0, sb);
                var op = GetProperty(node, "Operator");
                string opStr = op is string ? (string)op : TokenKindHelper.GetTokenString(op);
                sb.Append(" ").Append(opStr).Append(" ");
                WriteAstNode(GetProperty(node, "Right"), 0, sb);
            }

            // ReturnStatementAst
            else if (typeName == "ReturnStatementAst" || typeName == "MutableReturnStatementAst") {
                sb.Append(indentStr).Append("return ");
                WriteAstNode(GetProperty(node, "Pipeline"), 0, sb);
            }

            // ExitStatementAst
            else if (typeName == "ExitStatementAst" || typeName == "MutableExitStatementAst") {
                sb.Append(indentStr).Append("exit");
                var pipeline = GetProperty(node, "Pipeline");
                if (pipeline != null) {
                    sb.Append(" ");
                    WriteAstNode(pipeline, 0, sb);
                }
            }

            // ThrowStatementAst
            else if (typeName == "ThrowStatementAst" || typeName == "MutableThrowStatementAst") {
                sb.Append(indentStr).Append("throw ");
                WriteAstNode(GetProperty(node, "Pipeline"), 0, sb);
            }

            // BreakStatementAst
            else if (typeName == "BreakStatementAst" || typeName == "MutableBreakStatementAst") {
                sb.Append(indentStr).Append("break");
                var label = GetProperty(node, "Label");
                if (label != null) {
                    sb.Append(" ");
                    WriteAstNode(label, 0, sb);
                }
            }

            // ContinueStatementAst
            else if (typeName == "ContinueStatementAst" || typeName == "MutableContinueStatementAst") {
                sb.Append(indentStr).Append("continue");
                var label = GetProperty(node, "Label");
                if (label != null) {
                    sb.Append(" ");
                    WriteAstNode(label, 0, sb);
                }
            }

            // FunctionDefinitionAst
            else if (typeName == "FunctionDefinitionAst" || typeName == "MutableFunctionDefinitionAst") {
                var isFilter = GetProperty(node, "IsFilter");
                var isWorkflow = GetProperty(node, "IsWorkflow");
                string kw = (isFilter != null && (bool)isFilter) ? "filter" :
                           (isWorkflow != null && (bool)isWorkflow) ? "workflow" : "function";

                var name = GetProperty(node, "Name");
                sb.Append(indentStr).Append(kw).Append(" ").Append(name).Append(" ");

                var parameters = GetProperty(node, "Parameters") as IEnumerable;
                if (parameters != null) {
                    var list = new List<object>();
                    foreach (var p in parameters) list.Add(p);

                    if (list.Count > 0) {
                        sb.Append("(");
                        for (int i = 0; i < list.Count; i++) {
                            WriteAstNode(list[i], 0, sb);
                            if (i < list.Count - 1) sb.Append(", ");
                        }
                        sb.Append(") ");
                    }
                }

                sb.Append("{\n");
                WriteAstNode(GetProperty(node, "Body"), indentLevel + 1, sb);
                sb.Append(indentStr).Append("}");
            }

            // WhileStatementAst
            else if (typeName == "WhileStatementAst" || typeName == "MutableWhileStatementAst") {
                sb.Append(indentStr).Append("while (");
                WriteAstNode(GetProperty(node, "Condition"), 0, sb);
                sb.Append(") {\n");
                WriteAstNode(GetProperty(node, "Body"), indentLevel + 1, sb);
                sb.Append(indentStr).Append("}");
            }

            // DoWhileStatementAst
            else if (typeName == "DoWhileStatementAst" || typeName == "MutableDoWhileStatementAst") {
                sb.Append(indentStr).Append("do {\n");
                WriteAstNode(GetProperty(node, "Body"), indentLevel + 1, sb);
                sb.Append(indentStr).Append("} while (");
                WriteAstNode(GetProperty(node, "Condition"), 0, sb);
                sb.Append(")");
            }

            // DoUntilStatementAst
            else if (typeName == "DoUntilStatementAst" || typeName == "MutableDoUntilStatementAst") {
                sb.Append(indentStr).Append("do {\n");
                WriteAstNode(GetProperty(node, "Body"), indentLevel + 1, sb);
                sb.Append(indentStr).Append("} until (");
                WriteAstNode(GetProperty(node, "Condition"), 0, sb);
                sb.Append(")");
            }

            // ForStatementAst
            else if (typeName == "ForStatementAst" || typeName == "MutableForStatementAst") {
                sb.Append(indentStr).Append("for (");
                WriteAstNode(GetProperty(node, "Initializer"), 0, sb);
                sb.Append("; ");
                WriteAstNode(GetProperty(node, "Condition"), 0, sb);
                sb.Append("; ");
                WriteAstNode(GetProperty(node, "Iterator"), 0, sb);
                sb.Append(") {\n");
                WriteAstNode(GetProperty(node, "Body"), indentLevel + 1, sb);
                sb.Append(indentStr).Append("}");
            }

            // ForEachStatementAst
            else if (typeName == "ForEachStatementAst" || typeName == "MutableForEachStatementAst") {
                sb.Append(indentStr).Append("foreach (");
                WriteAstNode(GetProperty(node, "Variable"), 0, sb);
                sb.Append(" in ");
                var cond = GetProperty(node, "Condition");
                if (cond == null) cond = GetProperty(node, "Expression");
                WriteAstNode(cond, 0, sb);
                sb.Append(") {\n");
                WriteAstNode(GetProperty(node, "Body"), indentLevel + 1, sb);
                sb.Append(indentStr).Append("}");
            }

            // UnaryExpressionAst
            else if (typeName == "UnaryExpressionAst" || typeName == "MutableUnaryExpressionAst") {
                var kindObj = GetProperty(node, "TokenKind");
                string kind = kindObj != null ? kindObj.ToString() : "";
                var token = TokenKindHelper.GetTokenString(kindObj);
                
                if (kind == "PostfixPlusPlus" || kind == "PostfixMinusMinus") {
                    WriteAstNode(GetProperty(node, "Child"), 0, sb);
                    sb.Append(token);
                } else {
                    sb.Append(token);
                    WriteAstNode(GetProperty(node, "Child"), 0, sb);
                }
            }

            // SwitchStatementAst
            else if (typeName == "SwitchStatementAst" || typeName == "MutableSwitchStatementAst") {
                var label = GetProperty(node, "Label");
                if (label != null && !string.IsNullOrEmpty(label.ToString())) {
                    sb.Append(indentStr).Append(":").Append(label.ToString()).Append(" ");
                    sb.Append("switch");
                } else {
                    sb.Append(indentStr).Append("switch");
                }

                var flags = GetProperty(node, "Flags");
                if (flags != null) {
                    int flagsVal = Convert.ToInt32(flags);
                    if ((flagsVal & 1) != 0) sb.Append(" -CaseSensitive");
                    if ((flagsVal & 2) != 0) sb.Append(" -Regex");
                    if ((flagsVal & 4) != 0) sb.Append(" -Wildcard");
                    if ((flagsVal & 16) != 0) sb.Append(" -File");
                }

                var condition = GetProperty(node, "Condition");
                if (condition != null) {
                    sb.Append(" (");
                    WriteAstNode(condition, 0, sb);
                    sb.Append(")");
                }
                sb.Append(" {\n");

                var clauses = GetProperty(node, "Clauses") as IEnumerable;
                if (clauses != null) {
                    foreach (var c in clauses) {
                        var test = GetProperty(c, "Item1");
                        var body = GetProperty(c, "Item2");

                        sb.Append(indentStr).Append("    ");
                        WriteAstNode(test, 0, sb);
                        sb.Append(" { \n");
                        WriteAstNode(body, indentLevel + 2, sb);
                        sb.Append(indentStr).Append("    }");
                        sb.Append("\n");
                    }
                }

                var defaultClause = GetProperty(node, "Default");
                if (defaultClause != null) {
                    sb.Append(indentStr).Append("    default {\n");
                    WriteAstNode(defaultClause, indentLevel + 2, sb);
                    sb.Append(indentStr).Append("    }\n");
                }
                sb.Append(indentStr).Append("}");
            }

            // ConstantExpressionAst
            else if (typeName == "ConstantExpressionAst" || typeName == "MutableConstantExpressionAst") {
                var value = GetProperty(node, "Value");
                if (value == null) {
                    sb.Append("$null");
                } else if (value is bool) {
                    sb.Append((bool)value ? "$true" : "$false");
                } else if (value is string) {
                    string s = (string)value;
                    sb.Append("'").Append(s.Replace("'", "''")).Append("'");
                } else if (value is int || value is short || value is ushort || value is byte || value is sbyte) {
                    sb.Append(String.Format("0x{0:x}", value));
                } else if (value is long || value is ulong || value is uint) {
                    sb.Append(String.Format("0x{0:x}L", value));
                } else {
                    sb.Append(value.ToString());
                }
            }

            // StringConstantExpressionAst
            else if (typeName == "StringConstantExpressionAst" || typeName == "MutableStringConstantExpressionAst") {
                var value = GetProperty(node, "Value").ToString();
                var strTypeObj = GetProperty(node, "StringConstantType");
                string strType = strTypeObj != null ? strTypeObj.ToString() : "";

                if (strType == "SingleQuoted") {
                    sb.Append("'").Append(value.Replace("'", "''")).Append("'");
                } else if (strType == "DoubleQuoted") {
                    // Escape backtick, then quote, then dollar
                    string escaped = value.Replace("``", "````").Replace("\"", "``\"").Replace("$", "``$");
                    sb.Append("\"").Append(escaped).Append("\"");
                } else if (strType == "SingleQuotedHereString") {
                    sb.Append("@'\n").Append(value).Append("\n'@");
                } else if (strType == "DoubleQuotedHereString") {
                    sb.Append("@\"\n").Append(value).Append("\n\"@");
                } else {
                    // BareWord
                    // Only escape if it starts with something that could be a variable or parameter,
                    // or contains characters that definitely need escaping.
                    // Hyphen is generally safe in the middle of a word.
                    string escaped = value;
                    if (Regex.IsMatch(value, "[^a-zA-Z0-9_:]+")) {
                        escaped = Regex.Replace(value, "([^a-zA-Z0-9_:]+)", "`$1");
                    }
                    sb.Append(escaped);
                }
            }

            // ExpandableStringExpressionAst
            else if (typeName == "ExpandableStringExpressionAst" || typeName == "MutableExpandableStringExpressionAst") {
                var value = GetProperty(node, "Value").ToString();
                var strTypeObj = GetProperty(node, "StringConstantType");
                string strType = strTypeObj != null ? strTypeObj.ToString() : "";

                if (strType == "DoubleQuotedHereString") {
                    sb.Append("@\"\n").Append(value).Append("\n\"@");
                } else {
                    // Escape backtick, then quote. Do NOT escape dollar (it expands).
                    string escaped = value.Replace("``", "````").Replace("\"", "``\"");
                    sb.Append("\"").Append(escaped).Append("\"");
                }
            }

            // VariableExpressionAst
            else if (typeName == "VariableExpressionAst" || typeName == "MutableVariableExpressionAst") {
                var splatted = GetProperty(node, "Splatted");
                string prefix = (splatted != null && (bool)splatted) ? "@" : "$";

                var varPath = GetProperty(node, "VariablePath"); // string in Mutable, VariablePath in Native
                string path = "";
                if (varPath != null) {
                     // Check if it's Native VariablePath object
                     var userPath = GetProperty(varPath, "UserPath");
                     path = userPath != null ? userPath.ToString() : varPath.ToString();
                }
                
                // Wrap in braces if not a simple identifier (alphanumeric + underscore)
                // Also allowing : for scope/drive qualification if it looks simple otherwise?
                // Actually, ${scope:name} is valid. ${name} is valid.
                // If path contains special chars, wrap it.
                // Simple identifiers: [a-zA-Z0-9_]+ and maybe scope qualifiers like global: or env:
                // But simplified rule: if it matches ^[a-zA-Z0-9_:]+$ it might be safe?
                // Standard PS variable names allows ? and ^.
                // Let's stick to safe wrapping for anything suspicious.
                
                bool simple = Regex.IsMatch(path, "^[a-zA-Z0-9_:]+$");
                if (simple) {
                    sb.Append(prefix).Append(path);
                } else {
                    sb.Append(prefix).Append("{").Append(path).Append("}");
                }
            }

            // PipelineAst
            else if (typeName == "PipelineAst" || typeName == "MutablePipelineAst") {
                if (indentLevel > 0) sb.Append(indentStr);

                var pipelineElements = GetProperty(node, "PipelineElements") as IEnumerable;
                if (pipelineElements != null) {
                    var list = new List<object>();
                    foreach (var e in pipelineElements) list.Add(e);

                    for (int i = 0; i < list.Count; i++) {
                        WriteAstNode(list[i], 0, sb);
                        if (i < list.Count - 1) sb.Append(" | ");
                    }
                }
            }

            // CommandAst
            else if (typeName == "CommandAst" || typeName == "MutableCommandAst") {
                var invOp = GetProperty(node, "InvocationOperator");
                string op = (invOp != null && invOp.ToString() != "Unknown") ? TokenKindHelper.GetTokenString(invOp) : "";
                if (!string.IsNullOrEmpty(op)) sb.Append(op).Append(" ");

                var commandElements = GetProperty(node, "CommandElements") as IEnumerable;
                if (commandElements != null) {
                    var list = new List<object>();
                    foreach (var e in commandElements) list.Add(e);

                    for (int i = 0; i < list.Count; i++) {
                        WriteAstNode(list[i], 0, sb);
                        if (i < list.Count - 1) sb.Append(" ");
                    }
                }

                var redirections = GetProperty(node, "Redirections") as IEnumerable;
                if (redirections != null) {
                    foreach (var r in redirections) {
                        sb.Append(" ");
                        WriteAstNode(r, 0, sb);
                    }
                }
            }

            // CommandExpressionAst
            else if (typeName == "CommandExpressionAst" || typeName == "MutableCommandExpressionAst") {
                WriteAstNode(GetProperty(node, "Expression"), 0, sb);
                
                // CommandExpressionAst can also have redirections
                var redirections = GetProperty(node, "Redirections") as IEnumerable;
                if (redirections != null) {
                    foreach (var r in redirections) {
                        sb.Append(" ");
                        WriteAstNode(r, 0, sb);
                    }
                }
            }

            // CommandParameterAst
            else if (typeName == "CommandParameterAst" || typeName == "MutableCommandParameterAst") {
                sb.Append("-").Append(GetProperty(node, "ParameterName"));
                var argument = GetProperty(node, "Argument");
                if (argument != null) {
                    sb.Append(":");
                    WriteAstNode(argument, 0, sb);
                }
            }

            // FileRedirectionAst
            else if (typeName == "FileRedirectionAst" || typeName == "MutableFileRedirectionAst") {
                var from = GetProperty(node, "From");
                if (from == null) from = GetProperty(node, "FromStream");

                var append = GetProperty(node, "Append");
                bool isAppend = (append != null && (bool)append);
                
                // Format: [stream]>[>] filename
                // If stream is Output (1), it's optional, but explicit 1> is fine.
                // Standard PS: 2>, 3>, etc.
                // > or >> implies stream 1 if not specified, but AST has explicit stream.
                
                string streamId = "";
                if (from != null) {
                    string s = from.ToString();
                    if (s == "All") streamId = "*";
                    else if (s == "Output") streamId = "1"; // Usually implicit, but can be explicit
                    else if (s == "Error") streamId = "2";
                    else if (s == "Warning") streamId = "3";
                    else if (s == "Verbose") streamId = "4";
                    else if (s == "Debug") streamId = "5";
                    else if (s == "Information") streamId = "6";
                }

                // Optimization: if stream 1, we can omit '1' usually, but '1>' is also valid.
                // Let's stick to safe generation.
                // However, '*' must be *>, not number.
                
                if (streamId == "1") streamId = ""; // 1> is equivalent to >

                sb.Append(streamId).Append(isAppend ? ">>" : ">").Append(" ");
                WriteAstNode(GetProperty(node, "Location"), 0, sb);
            }

            // MergingRedirectionAst
            else if (typeName == "MergingRedirectionAst" || typeName == "MutableMergingRedirectionAst") {
                var from = GetProperty(node, "From");
                if (from == null) from = GetProperty(node, "FromStream");

                var to = GetProperty(node, "To");
                if (to == null) to = GetProperty(node, "ToStream");
                
                string fromId = "";
                if (from != null) {
                    string s = from.ToString();
                    if (s == "All") fromId = "*";
                    else if (s == "Output") fromId = "1";
                    else if (s == "Error") fromId = "2";
                    else if (s == "Warning") fromId = "3";
                    else if (s == "Verbose") fromId = "4";
                    else if (s == "Debug") fromId = "5";
                    else if (s == "Information") fromId = "6";
                }

                string toId = "&1"; // Default to &1 (Output)
                if (to != null) {
                    string s = to.ToString();
                    if (s == "Output") toId = "&1";
                    else if (s == "Error") toId = "&2";
                    // Only Output and Error are valid targets for merging usually
                }

                sb.Append(fromId).Append(">").Append(toId);
            }

            // BinaryExpressionAst
            else if (typeName == "BinaryExpressionAst" || typeName == "MutableBinaryExpressionAst") {
                WriteAstNode(GetProperty(node, "Left"), 0, sb);
                var op = GetProperty(node, "Operator");
                string opStr = op is string ? (string)op : TokenKindHelper.GetTokenString(op);
                sb.Append(" ").Append(opStr).Append(" ");
                WriteAstNode(GetProperty(node, "Right"), 0, sb);
            }

            // InvokeMemberExpressionAst
            else if (typeName == "InvokeMemberExpressionAst" || typeName == "MutableInvokeMemberExpressionAst") {
                var staticFlag = GetProperty(node, "Static");
                string op = (staticFlag != null && (bool)staticFlag) ? "::" : ".";
                WriteAstNode(GetProperty(node, "Expression"), 0, sb);
                sb.Append(op);
                
                var member = GetProperty(node, "Member");
                bool handled = false;
                if (member != null && member.GetType().Name == "MutableStringConstantExpressionAst") {
                    var val = GetProperty(member, "Value") as string;
                    if (val != null && Regex.IsMatch(val, "^[a-zA-Z_][a-zA-Z0-9_]*$")) {
                        sb.Append(val);
                        handled = true;
                    }
                }
                if (!handled) WriteAstNode(member, 0, sb);

                sb.Append("(");

                var arguments = GetProperty(node, "Arguments") as IEnumerable;
                if (arguments != null) {
                    var list = new List<object>();
                    foreach (var a in arguments) list.Add(a);

                    for (int i = 0; i < list.Count; i++) {
                        WriteAstNode(list[i], 0, sb);
                        if (i < list.Count - 1) sb.Append(", ");
                    }
                }
                sb.Append(")");
            }

            // MemberExpressionAst
            else if (typeName == "MemberExpressionAst" || typeName == "MutableMemberExpressionAst") {
                var staticFlag = GetProperty(node, "Static");
                string op = (staticFlag != null && (bool)staticFlag) ? "::" : ".";
                WriteAstNode(GetProperty(node, "Expression"), 0, sb);
                sb.Append(op);
                
                var member = GetProperty(node, "Member");
                bool handled = false;
                if (member != null && member.GetType().Name == "MutableStringConstantExpressionAst") {
                    var val = GetProperty(member, "Value") as string;
                    if (val != null && Regex.IsMatch(val, "^[a-zA-Z_][a-zA-Z0-9_]*$")) {
                        sb.Append(val);
                        handled = true;
                    }
                }
                if (!handled) WriteAstNode(member, 0, sb);
            }

            // IfStatementAst
            else if (typeName == "IfStatementAst" || typeName == "MutableIfStatementAst") {
                sb.Append(indentStr);
                bool first = true;

                var clauses = GetProperty(node, "Clauses") as IEnumerable;
                if (clauses != null) {
                    foreach (var clause in clauses) {
                        var test = GetProperty(clause, "Item1");
                        var body = GetProperty(clause, "Item2");

                        if (!first) {
                            sb.Append(" elseif ");
                        } else {
                            sb.Append("if ");
                        }
                        sb.Append("(");
                        WriteAstNode(test, 0, sb);
                        sb.Append(") {\n");
                        WriteAstNode(body, indentLevel + 1, sb);
                        sb.Append(indentStr).Append("}");
                        first = false;
                    }
                }

                var elseClause = GetProperty(node, "ElseClause");
                if (elseClause != null) {
                    sb.Append(" else {\n");
                    WriteAstNode(elseClause, indentLevel + 1, sb);
                    sb.Append(indentStr).Append("}");
                }
            }

            // TrapStatementAst
            else if (typeName == "TrapStatementAst" || typeName == "MutableTrapStatementAst") {
                sb.Append(indentStr).Append("trap");
                var type = GetProperty(node, "TrapType");
                if (type != null) {
                    sb.Append(" ");
                    WriteAstNode(type, 0, sb);
                }
                sb.Append(" {\n");
                WriteAstNode(GetProperty(node, "Body"), indentLevel + 1, sb);
                sb.Append(indentStr).Append("}");
            }

            // DataStatementAst
            else if (typeName == "DataStatementAst" || typeName == "MutableDataStatementAst") {
                sb.Append(indentStr).Append("data");
                var variable = GetProperty(node, "Variable");
                if (variable != null) {
                    sb.Append(" ").Append(variable);
                }
                var commands = GetProperty(node, "CommandsAllowed") as IEnumerable;
                if (commands != null) {
                     var list = new List<object>();
                     foreach (var c in commands) list.Add(c);
                     if (list.Count > 0) {
                         sb.Append(" -SupportedCommand ");
                         for(int i=0; i<list.Count; i++) {
                             WriteAstNode(list[i], 0, sb);
                             if (i < list.Count - 1) sb.Append(", ");
                         }
                     }
                }
                sb.Append(" {\n");
                WriteAstNode(GetProperty(node, "Body"), indentLevel + 1, sb);
                sb.Append(indentStr).Append("}");
            }

            // BlockStatementAst
            else if (typeName == "BlockStatementAst" || typeName == "MutableBlockStatementAst") {
                sb.Append("{\n");
                WriteAstNode(GetProperty(node, "Body"), indentLevel + 1, sb);
                sb.Append(indentStr).Append("}");
            }

            // StatementBlockAst
            else if (typeName == "StatementBlockAst" || typeName == "NamedBlockAst" ||
                     typeName == "MutableStatementBlockAst") {
                var statements = GetProperty(node, "Statements") as IEnumerable;
                if (statements != null) {
                    foreach (var s in statements) {
                        WriteAstNode(s, indentLevel, sb);
                        sb.Append("\n");
                    }
                }
            }

            // TryStatementAst
            else if (typeName == "TryStatementAst" || typeName == "MutableTryStatementAst") {
                sb.Append(indentStr).Append("try {\n");
                WriteAstNode(GetProperty(node, "Body"), indentLevel + 1, sb);
                sb.Append(indentStr).Append("}");

                var catchClauses = GetProperty(node, "CatchClauses") as IEnumerable;
                if (catchClauses != null) {
                    foreach (var catchClause in catchClauses) {
                        sb.Append(" ");
                        WriteCatchClause(catchClause, indentLevel, sb);
                    }
                }

                var finallyClause = GetProperty(node, "Finally");
                if (finallyClause != null) {
                    sb.Append(" finally {\n");
                    WriteAstNode(finallyClause, indentLevel + 1, sb);
                    sb.Append(indentStr).Append("}");
                }
            }

            // ArrayExpressionAst
            else if (typeName == "ArrayExpressionAst" || typeName == "MutableArrayExpressionAst") {
                sb.Append("@(");
                WriteAstNode(GetProperty(node, "SubExpression"), 0, sb);
                sb.Append(")");
            }

            // IndexExpressionAst
            else if (typeName == "IndexExpressionAst" || typeName == "MutableIndexExpressionAst") {
                WriteAstNode(GetProperty(node, "Target"), 0, sb);
                sb.Append("[");
                WriteAstNode(GetProperty(node, "Index"), 0, sb);
                sb.Append("]");
            }

            // ScriptBlockExpressionAst
            else if (typeName == "ScriptBlockExpressionAst" || typeName == "MutableScriptBlockExpressionAst") {
                sb.Append("{\n");
                WriteAstNode(GetProperty(node, "ScriptBlock"), indentLevel + 1, sb);
                sb.Append(indentStr).Append("}");
            }

            // TypeExpressionAst
            else if (typeName == "TypeExpressionAst" || typeName == "MutableTypeExpressionAst") {
                var typeNameObj = GetProperty(node, "TypeName");
                string t = "";
                if (typeNameObj != null) {
                    var fullName = GetProperty(typeNameObj, "FullName");
                    t = fullName != null ? fullName.ToString() : typeNameObj.ToString();
                }
                sb.Append("[").Append(t).Append("]");
            }

            // ParenExpressionAst
            else if (typeName == "ParenExpressionAst" || typeName == "MutableParenExpressionAst") {
                sb.Append("(");
                WriteAstNode(GetProperty(node, "Pipeline"), 0, sb);
                sb.Append(")");
            }

            // ArrayLiteralAst
            else if (typeName == "ArrayLiteralAst" || typeName == "MutableArrayLiteralAst") {
                var elements = GetProperty(node, "Elements") as IEnumerable;
                if (elements != null) {
                    var list = new List<object>();
                    foreach (var e in elements) list.Add(e);

                    if (list.Count == 1) {
                        sb.Append(",");
                        WriteAstNode(list[0], 0, sb);
                    } else {
                        for (int i = 0; i < list.Count; i++) {
                            WriteAstNode(list[i], 0, sb);
                            if (i < list.Count - 1) sb.Append(", ");
                        }
                    }
                }
            }

            // ConvertExpressionAst
            else if (typeName == "ConvertExpressionAst" || typeName == "MutableConvertExpressionAst") {
                WriteAstNode(GetProperty(node, "Type"), 0, sb);
                WriteAstNode(GetProperty(node, "Child"), 0, sb);
            }

            // AttributedExpressionAst
            else if (typeName == "AttributedExpressionAst" || typeName == "MutableAttributedExpressionAst") {
                WriteAstNode(GetProperty(node, "Attribute"), 0, sb);
                WriteAstNode(GetProperty(node, "Child"), 0, sb);
            }

            // SubExpressionAst
            else if (typeName == "SubExpressionAst" || typeName == "MutableSubExpressionAst") {
                sb.Append("$").Append("(");
                WriteAstNode(GetProperty(node, "SubExpression"), 0, sb);
                sb.Append(")");
            }

            // UsingExpressionAst
            else if (typeName == "UsingExpressionAst" || typeName == "MutableUsingExpressionAst") {
                sb.Append("$" + "using:");
                WriteAstNode(GetProperty(node, "SubExpression"), 0, sb);
            }

            // HashtableAst
            else if (typeName == "HashtableAst" || typeName == "MutableHashtableAst") {
                var kvPairs = GetProperty(node, "KeyValuePairs") as IEnumerable;
                if (kvPairs == null) {
                    sb.Append("@{}");
                } else {
                    var list = new List<object>();
                    foreach (var p in kvPairs) list.Add(p);

                    if (list.Count == 0) {
                        sb.Append("@{}");
                    } else {
                        sb.Append("@{\n");
                        foreach (var pair in list) {
                            var k = GetProperty(pair, "Item1");
                            if (k == null) k = GetProperty(pair, "Key");
                            var v = GetProperty(pair, "Item2");
                            if (v == null) v = GetProperty(pair, "Value");

                            sb.Append(indentStr).Append("    ");
                            WriteAstNode(k, 0, sb);
                            sb.Append(" = ");
                            WriteAstNode(v, indentLevel + 1, sb);
                            sb.Append("\n");
                        }
                        sb.Append(indentStr).Append("}");
                    }
                }
            }

            // PipelineChainAst
            else if (typeName == "PipelineChainAst" || typeName == "MutablePipelineChainAst") {
                var op = GetProperty(node, "Operator");
                string opStr = (op != null && op.ToString() == "And") ? "&&" : "||";

                // Native AST uses LhsPipelineChain/RhsPipeline, Mutable uses Left/Right
                var left = GetProperty(node, "Left");
                if (left == null) left = GetProperty(node, "LhsPipelineChain");

                var right = GetProperty(node, "Right");
                if (right == null) right = GetProperty(node, "RhsPipeline");

                WriteAstNode(left, 0, sb);
                sb.Append(" ").Append(opStr).Append(" ");
                WriteAstNode(right, 0, sb);
            }

            // TypeDefinitionAst
            else if (typeName == "TypeDefinitionAst" || typeName == "MutableTypeDefinitionAst") {
                var attributes = GetProperty(node, "Attributes") as IEnumerable;
                if (attributes != null) {
                    foreach (var attr in attributes) {
                        sb.Append(indentStr);
                        WriteAstNode(attr, 0, sb);
                        sb.Append("\n");
                    }
                }

                sb.Append(indentStr);
                var isEnum = GetProperty(node, "IsEnum");
                var isInterface = GetProperty(node, "IsInterface");

                if (isEnum != null && (bool)isEnum) {
                    sb.Append("enum ");
                } else if (isInterface != null && (bool)isInterface) {
                    sb.Append("interface ");
                } else {
                    sb.Append("class ");
                }

                sb.Append(GetProperty(node, "Name"));

                var baseTypes = GetProperty(node, "BaseTypes") as IEnumerable;
                if (baseTypes != null) {
                    var list = new List<object>();
                    foreach (var bt in baseTypes) list.Add(bt);

                    if (list.Count > 0) {
                        sb.Append(" : ");
                        for (int i = 0; i < list.Count; i++) {
                            WriteAstNode(list[i], 0, sb);
                            if (i < list.Count - 1) sb.Append(", ");
                        }
                    }
                }
                sb.Append(" {\n");

                var members = GetProperty(node, "Members") as IEnumerable;
                if (members != null) {
                    bool enumType = (isEnum != null && (bool)isEnum);
                    foreach (var m in members) {
                        if (enumType) {
                            sb.Append(indentStr).Append("    ");
                            var attrs = GetProperty(m, "Attributes") as IEnumerable;
                            if (attrs != null) {
                                foreach (var a in attrs) {
                                    WriteAstNode(a, 0, sb);
                                    sb.Append(" ");
                                }
                            }
                            sb.Append(GetProperty(m, "Name"));
                            var initVal = GetProperty(m, "InitialValue");
                            if (initVal != null) {
                                sb.Append(" = ");
                                WriteAstNode(initVal, 0, sb);
                            }
                            sb.Append("\n");
                        } else {
                            WriteAstNode(m, indentLevel + 1, sb);
                            sb.Append("\n");
                        }
                    }
                }
                sb.Append(indentStr).Append("}");
            }

            // PropertyMemberAst
            else if (typeName == "PropertyMemberAst" || typeName == "MutablePropertyMemberAst") {
                sb.Append(indentStr);
                var attributes = GetProperty(node, "Attributes") as IEnumerable;
                if (attributes != null) {
                    foreach (var attr in attributes) {
                        WriteAstNode(attr, 0, sb);
                        sb.Append(" ");
                    }
                }

                // Native uses IsStatic, Mutable uses Static
                var staticFlag = GetProperty(node, "Static");
                if (staticFlag == null) staticFlag = GetProperty(node, "IsStatic");
                if (staticFlag != null && (bool)staticFlag) sb.Append("static ");

                var propType = GetProperty(node, "PropertyType");
                if (propType != null) {
                    WriteAstNode(propType, 0, sb);
                    sb.Append(" ");
                }

                sb.Append("$").Append(GetProperty(node, "Name"));

                var initVal = GetProperty(node, "InitialValue");
                if (initVal != null) {
                    sb.Append(" = ");
                    WriteAstNode(initVal, 0, sb);
                }
            }

            // FunctionMemberAst
            else if (typeName == "FunctionMemberAst" || typeName == "MutableFunctionMemberAst") {
                sb.Append(indentStr);
                var attributes = GetProperty(node, "Attributes") as IEnumerable;
                if (attributes != null) {
                    foreach (var attr in attributes) {
                        WriteAstNode(attr, 0, sb);
                        sb.Append(" ");
                    }
                }

                // Native uses IsStatic, Mutable uses Static
                var staticFlag = GetProperty(node, "Static");
                if (staticFlag == null) staticFlag = GetProperty(node, "IsStatic");
                if (staticFlag != null && (bool)staticFlag) sb.Append("static ");

                var retType = GetProperty(node, "ReturnType");
                if (retType != null) {
                    WriteAstNode(retType, 0, sb);
                    sb.Append(" ");
                }

                sb.Append(GetProperty(node, "Name")).Append("(");

                var parameters = GetProperty(node, "Parameters") as IEnumerable;
                if (parameters != null) {
                    var list = new List<object>();
                    foreach (var p in parameters) list.Add(p);

                    for (int i = 0; i < list.Count; i++) {
                        WriteAstNode(list[i], 0, sb);
                        if (i < list.Count - 1) sb.Append(", ");
                    }
                }
                sb.Append(") {\n");
                WriteAstNode(GetProperty(node, "Body"), indentLevel, sb);
                sb.Append(indentStr).Append("}");
            }

            // ErrorStatementAst / ErrorExpressionAst
            else if (typeName == "ErrorStatementAst" || typeName == "MutableErrorStatementAst" ||
                     typeName == "ErrorExpressionAst" || typeName == "MutableErrorExpressionAst") {
                
                var originalText = GetProperty(node, "OriginalText");
                if (originalText != null && !string.IsNullOrEmpty(originalText.ToString())) {
                    sb.Append(originalText.ToString());
                } else {
                    // Fallback for Native AST: Use Extent.Text
                    var extent = GetProperty(node, "Extent");
                    if (extent != null) {
                        var text = GetProperty(extent, "Text");
                        if (text != null && !string.IsNullOrEmpty(text.ToString())) {
                            sb.Append(text.ToString());
                            return;
                        }
                    }

                    var nested = GetProperty(node, "NestedAst") as IEnumerable;
                    bool hasNested = false;
                    if (nested != null) {
                        foreach(var n in nested) { hasNested = true; break; }
                    }

                    if (hasNested) {
                        if (nested != null) {
                            bool first = true;
                            foreach (var n in nested) {
                                if (!first) sb.Append(" ");
                                WriteAstNode(n, 0, sb);
                                first = false;
                            }
                        }
                    } else {
                        var msg = GetProperty(node, "ErrorMessage");
                        sb.Append("# ERROR: ").Append(msg ?? "Native ErrorAst");
                    }
                }
            }

            else {
                sb.Append(indentStr).Append("# Unknown Node: ").Append(typeName).Append("\n");
            }
        }

        private static void WriteCatchClause(object catchNode, int indentLevel, StringBuilder sb) {
            if (catchNode == null) return;
            string indentStr = new string(' ', indentLevel * 4);

            sb.Append("catch ");
            var catchTypes = GetProperty(catchNode, "CatchTypes") as IEnumerable;
            if (catchTypes != null) {
                var list = new List<object>();
                foreach (var ct in catchTypes) list.Add(ct);

                if (list.Count > 0) {
                    for (int i = 0; i < list.Count; i++) {
                        WriteAstNode(list[i], 0, sb);
                        if (i < list.Count - 1) sb.Append(", ");
                    }
                    sb.Append(" ");
                }
            }

            sb.Append("{\n");
            WriteAstNode(GetProperty(catchNode, "Body"), indentLevel + 1, sb);
            sb.Append(indentStr).Append("}");
        }
    }
}

namespace DeobfuscatorKit {
    using DeobfuscatorInternal; 

    public class DeobfuscatorContext {
        public Dictionary<string, object> Variables { get; set; }
        public HashSet<string> TaintedVariables { get; set; }
        public Dictionary<string, MutableFunctionDefinitionAst> Functions { get; set; } 
        
        public DeobfuscatorContext() {
            Variables = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            TaintedVariables = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            Functions = new Dictionary<string, MutableFunctionDefinitionAst>(StringComparer.OrdinalIgnoreCase);
        }

        public void SetVar(string name, object val) {
            if (TaintedVariables.Contains(name)) return;
            Variables[name] = val;
        }

        public void Taint(string name) {
            TaintedVariables.Add(name);
            if (Variables.ContainsKey(name)) Variables.Remove(name);
        }

        public object GetVar(string name) {
            if (Variables.ContainsKey(name)) return Variables[name];
            return null;
        }
        
        public bool IsConstant(string name) { return Variables.ContainsKey(name); }
        
        public void Merge(DeobfuscatorContext other) {
            foreach (var t in other.TaintedVariables) Taint(t);
            foreach (var key in other.Variables.Keys) Taint(key);
            foreach (var kv in other.Functions) Functions[kv.Key] = kv.Value;
        }

        public DeobfuscatorContext Clone() {
            var newCtx = new DeobfuscatorContext();
            foreach (var kv in Variables) newCtx.Variables[kv.Key] = kv.Value;
            foreach (var t in TaintedVariables) newCtx.TaintedVariables.Add(t);
            foreach (var kv in Functions) newCtx.Functions[kv.Key] = kv.Value;
            return newCtx;
        }
    }

    public class Deobfuscator {
        private HashSet<string> AllowedPrefixes;
        private static readonly object RemoveStatement = new object();

        public Deobfuscator() {
            AllowedPrefixes = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
                "System.String", "string",
                "System.Text", 
                "System.Convert", 
                "System.BitConverter", 
                "System.Math",
                "System.Security.Cryptography",
                "System.IO.MemoryStream",
                "System.IO.Compression",
                "System.Array"
            };
        }

        private bool IsTypeAllowed(string typeName) {
            if (string.IsNullOrEmpty(typeName)) return false;
            string fullTypeName = typeName.Contains(".") ? typeName : "System." + typeName;

            foreach (var prefix in AllowedPrefixes) {
                if (fullTypeName.Equals(prefix, StringComparison.OrdinalIgnoreCase) ||
                    fullTypeName.StartsWith(prefix + ".", StringComparison.OrdinalIgnoreCase)) {
                    return true;
                }
            }
            return false;
        }

        public void DeobfuscateAndSave(string scriptContent, string originalFilePath) {
            ScriptBlockAst ast = (ScriptBlockAst)Parser.ParseInput(scriptContent, out Token[] tokens, out ParseError[] errors);
            MutableAst mutableAst = MutableAstConverter.Convert(ast);
            
            string dir = Path.GetDirectoryName(originalFilePath);
            string name = Path.GetFileNameWithoutExtension(originalFilePath);
            string basePath = Path.Combine(dir, name + "_deobfuscated");
            
            int maxPasses = 20;
            string lastCode = AstSourceCodeGenerator.ConvertToSourceCode(mutableAst);
            
            for (int pass = 1; pass <= maxPasses; pass++) {
                var ctx = new DeobfuscatorContext();
                Visit(mutableAst, ctx);
                RemoveDeadCode(mutableAst);

                string codeAfter = AstSourceCodeGenerator.ConvertToSourceCode(mutableAst);
                
                // Save intermediate pass
                string passFileName = basePath + "_" + pass.ToString("D3") + ".ps1";
                File.WriteAllText(passFileName, codeAfter, Encoding.UTF8);

                if (lastCode == codeAfter) {
                    // No change, this is the final result (same as previous pass, but we saved it as current pass)
                    // Save final result
                    string finalFileName = basePath + ".ps1";
                    File.WriteAllText(finalFileName, codeAfter, Encoding.UTF8);
                    break;
                }
                lastCode = codeAfter;
                
                // If this is the last pass allowed
                if (pass == maxPasses) {
                    string finalFileName = basePath + ".ps1";
                    File.WriteAllText(finalFileName, codeAfter, Encoding.UTF8);
                }
            }
        }

        public object Visit(object node, DeobfuscatorContext ctx) {
            if (node == null) return null;
            if (!(node is MutableAst)) return null;
            
            var mNode = (MutableAst)node;
            string type = mNode.GetType().Name;

            if (type == "MutableScriptBlockAst") {
                var sb = (MutableScriptBlockAst)mNode;
                Visit(sb.EndBlock, ctx);
            }
            else if (type == "MutableStatementBlockAst") {
                var sb = (MutableStatementBlockAst)mNode;
                for (int i = sb.Statements.Count - 1; i >= 0; i--) {
                    var replacement = Visit(sb.Statements[i], ctx);
                    if (replacement == RemoveStatement) {
                        sb.Statements.RemoveAt(i);
                    }
                    else if (replacement != null && replacement is MutableStatementAst rStmt) {
                        sb.Statements[i] = rStmt;
                    }
                }
            }
            else if (type == "MutableFunctionDefinitionAst") {
                var fd = (MutableFunctionDefinitionAst)mNode;
                ctx.Functions[fd.Name] = fd;
                var innerCtx = ctx.Clone();
                Visit(fd.Body, innerCtx);
            }
            else if (type == "MutableAssignmentStatementAst") {
                var assign = (MutableAssignmentStatementAst)mNode;
                var newRight = Visit(assign.Right, ctx);
                if (newRight != null && newRight is MutableStatementAst rStmt) assign.Right = rStmt;

                var varName = GetVarName(assign.Left);
                if (varName != null) {
                    if (assign.Left.NodeType == "MemberExpressionAst") {
                        TryEvaluateAssignmentToMember(assign, ctx);
                    }
                    var constVal = TryGetConstantValue(assign.Right);
                    if (constVal != null) ctx.SetVar(varName, constVal);
                    else ctx.Taint(varName);
                }
            }
            else if (type == "MutableIfStatementAst") {
                var ifStmt = (MutableIfStatementAst)mNode;
                foreach (var clause in ifStmt.Clauses) {
                    Visit(clause.Item1, ctx);
                    var branchCtx = ctx.Clone();
                    Visit(clause.Item2, branchCtx);
                    ctx.Merge(branchCtx);
                }
                if (ifStmt.ElseClause != null) {
                    var branchCtx = ctx.Clone();
                    Visit(ifStmt.ElseClause, branchCtx);
                    ctx.Merge(branchCtx);
                }
                return FoldIf(ifStmt);
            }
            else if (type == "MutablePipelineAst") {
                var pipe = (MutablePipelineAst)mNode;
                for (int i = 0; i < pipe.PipelineElements.Count; i++) {
                    var res = Visit(pipe.PipelineElements[i], ctx);
                    if (res != null && res is MutableAst resAst) {
                         if (resAst is MutableExpressionAst exprAst) {
                             var ce = new MutableCommandExpressionAst();
                             ce.Expression = exprAst;
                             pipe.PipelineElements[i] = ce;
                         } else if (resAst is MutableCommandBaseAst cmdBase) {
                             pipe.PipelineElements[i] = cmdBase;
                         }
                    }
                }
                return TryEvaluateIntCharPipeline(pipe);
            }
            else if (type == "MutableCommandParameterAst") {
                var cp = (MutableCommandParameterAst)mNode;
                if (cp.Argument != null) {
                    var res = Visit(cp.Argument, ctx);
                    if (res != null && res is MutableExpressionAst expr) cp.Argument = expr;
                }
            }
            else if (type == "MutableCommandAst") {
                var cmd = (MutableCommandAst)mNode;
                for (int i = 0; i < cmd.CommandElements.Count; i++) {
                    var res = Visit(cmd.CommandElements[i], ctx);
                    if (res != null && res is MutableAst rAst) cmd.CommandElements[i] = rAst;
                }
                return TryEvaluateCommand(cmd, ctx);
            }
            else if (type == "MutableCommandExpressionAst") {
                var ce = (MutableCommandExpressionAst)mNode;
                var res = Visit(ce.Expression, ctx);
                if (res != null && res is MutableExpressionAst expr) ce.Expression = expr;
            }
            else if (type == "MutableBinaryExpressionAst") {
                var bin = (MutableBinaryExpressionAst)mNode;
                var l = Visit(bin.Left, ctx);
                if (l != null && l is MutableExpressionAst lExpr) bin.Left = lExpr;
                var r = Visit(bin.Right, ctx);
                if (r != null && r is MutableExpressionAst rExpr) bin.Right = rExpr;
                return FoldBinary(bin);
            }
            else if (type == "MutableVariableExpressionAst") {
                var ve = (MutableVariableExpressionAst)mNode;
                var name = GetVarName(ve);
                if (name != null && ctx.IsConstant(name)) {
                    var val = ctx.GetVar(name);
                    return CreateConstantNode(val);
                }
            }
            else if (type == "MutableInvokeMemberExpressionAst") {
                var ime = (MutableInvokeMemberExpressionAst)mNode;
                var expr = Visit(ime.Expression, ctx);
                if (expr != null && expr is MutableExpressionAst e) ime.Expression = e;
                
                var mem = Visit(ime.Member, ctx);
                if (mem != null && mem is MutableExpressionAst m) ime.Member = m;

                // Intercept [array]::Reverse($var) to update context variable in-place
                if (ime.Static && ime.Expression is MutableTypeExpressionAst te && 
                   (te.TypeName.Equals("System.Array", StringComparison.OrdinalIgnoreCase) || te.TypeName.Equals("array", StringComparison.OrdinalIgnoreCase))) {
                     
                     var methodName = TryGetConstantValue(ime.Member) as string;
                     if (string.Equals(methodName, "Reverse", StringComparison.OrdinalIgnoreCase) && 
                         ime.Arguments.Count == 1 && 
                         ime.Arguments[0] is MutableVariableExpressionAst ve) {
                         
                         string varName = GetVarName(ve);
                         if (varName != null && ctx.IsConstant(varName)) {
                             object val = ctx.GetVar(varName);
                             if (val is Array arr) {
                                 Array.Reverse(arr);
                                 return RemoveStatement;
                             }
                         }
                     }
                }

                for (int i = 0; i < ime.Arguments.Count; i++) {
                    var res = Visit(ime.Arguments[i], ctx);
                    if (res != null && res is MutableExpressionAst arg) ime.Arguments[i] = arg;
                }
                return TryEvaluateInvoke(ime, ctx);
            }
            else if (type == "MutableMemberExpressionAst") {
                var me = (MutableMemberExpressionAst)mNode;
                var expr = Visit(me.Expression, ctx);
                if (expr != null && expr is MutableExpressionAst e) me.Expression = e;
                
                var mem = Visit(me.Member, ctx);
                if (mem != null && mem is MutableExpressionAst m) me.Member = m;

                return TryEvaluateMember(me, ctx);
            }
            else if (type == "MutableSubExpressionAst") {
                var sub = (MutableSubExpressionAst)mNode;
                Visit(sub.SubExpression, ctx);
                
                if (sub.SubExpression.Statements.Count == 1) {
                    var stmt = sub.SubExpression.Statements[0];
                    if (stmt is MutablePipelineAst pipe && pipe.PipelineElements.Count == 1) {
                        if (pipe.PipelineElements[0] is MutableCommandExpressionAst ce) {
                            var val = TryGetConstantValue(ce.Expression);
                            if (val != null) return CreateConstantNode(val);
                        }
                    }
                }
            }
            else if (type == "MutableParenExpressionAst") {
                var pe = (MutableParenExpressionAst)mNode;
                var res = Visit(pe.Pipeline, ctx);
                if (res != null && res is MutableStatementAst s) pe.Pipeline = s;
                
                if (pe.Pipeline is MutablePipelineAst pipe && pipe.PipelineElements.Count == 1) {
                    var elem = pipe.PipelineElements[0];
                    if (elem is MutableCommandExpressionAst ce) return ce.Expression;
                }
                if (pe.Pipeline is MutableExpressionAst) return pe.Pipeline;
            }
            else if (type == "MutableTryStatementAst") {
                var tryStmt = (MutableTryStatementAst)mNode;
                var branchCtx = ctx.Clone();
                Visit(tryStmt.Body, branchCtx);
                ctx.Merge(branchCtx);
                foreach (var catchClause in tryStmt.CatchClauses) {
                    var catchCtx = ctx.Clone();
                    Visit(catchClause.Body, catchCtx);
                    ctx.Merge(catchCtx);
                }
                if (tryStmt.Finally != null) {
                    var finallyCtx = ctx.Clone();
                    Visit(tryStmt.Finally, finallyCtx);
                    ctx.Merge(finallyCtx);
                }
            }
            else if (type == "MutableWhileStatementAst") {
                var whileStmt = (MutableWhileStatementAst)mNode;
                Visit(whileStmt.Condition, ctx);
                var branchCtx = ctx.Clone();
                Visit(whileStmt.Body, branchCtx);
                ctx.Merge(branchCtx);
            }
            else if (type == "MutableDoWhileStatementAst") {
                var doWhile = (MutableDoWhileStatementAst)mNode;
                Visit(doWhile.Condition, ctx);
                var branchCtx = ctx.Clone();
                Visit(doWhile.Body, branchCtx);
                ctx.Merge(branchCtx);
            }
            else if (type == "MutableDoUntilStatementAst") {
                var doUntil = (MutableDoUntilStatementAst)mNode;
                Visit(doUntil.Condition, ctx);
                var branchCtx = ctx.Clone();
                Visit(doUntil.Body, branchCtx);
                ctx.Merge(branchCtx);
            }
            else if (type == "MutableForStatementAst") {
                var forStmt = (MutableForStatementAst)mNode;
                Visit(forStmt.Initializer, ctx);
                Visit(forStmt.Condition, ctx);
                Visit(forStmt.Iterator, ctx);
                var branchCtx = ctx.Clone();
                Visit(forStmt.Body, branchCtx);
                ctx.Merge(branchCtx);
            }
            else if (type == "MutableForEachStatementAst") {
                var forEach = (MutableForEachStatementAst)mNode;
                var loopVar = GetVarName(forEach.Variable);
                if (loopVar != null) ctx.Taint(loopVar);
                Visit(forEach.Condition, ctx);
                var branchCtx = ctx.Clone();
                Visit(forEach.Body, branchCtx);
                ctx.Merge(branchCtx);
            }
            else if (type == "MutableSwitchStatementAst") {
                var sw = (MutableSwitchStatementAst)mNode;
                Visit(sw.Condition, ctx);
                foreach (var clause in sw.Clauses) {
                    Visit(clause.Item1, ctx);
                    var branchCtx = ctx.Clone();
                    Visit(clause.Item2, branchCtx);
                    ctx.Merge(branchCtx);
                }
                if (sw.Default != null) {
                    var branchCtx = ctx.Clone();
                    Visit(sw.Default, branchCtx);
                    ctx.Merge(branchCtx);
                }
            }
            else if (type == "MutableBlockStatementAst") {
                var blk = (MutableBlockStatementAst)mNode;
                Visit(blk.Body, ctx);
            }
            else if (type == "MutableTrapStatementAst") {
                var trap = (MutableTrapStatementAst)mNode;
                var trapCtx = ctx.Clone();
                Visit(trap.Body, trapCtx);
                ctx.Merge(trapCtx);
            }
            else if (type == "MutableReturnStatementAst") {
                var ret = (MutableReturnStatementAst)mNode;
                if (ret.Pipeline != null) Visit(ret.Pipeline, ctx);
            }
             else if (type == "MutableExitStatementAst") {
                var ext = (MutableExitStatementAst)mNode;
                if (ext.Pipeline != null) Visit(ext.Pipeline, ctx);
            }
            else if (type == "MutableThrowStatementAst") {
                var th = (MutableThrowStatementAst)mNode;
                if (th.Pipeline != null) Visit(th.Pipeline, ctx);
            }

            return null;
        }

        private object FoldIf(MutableIfStatementAst node) {
            if (node.Clauses.Count > 0) {
                var cond = TryGetConstantValue(node.Clauses[0].Item1);
                if (cond != null) {
                    bool bCond = false;
                    if (LanguagePrimitives.IsTrue(cond)) bCond = true;
                    
                    if (bCond) return node.Clauses[0].Item2;
                    else {
                        if (node.Clauses.Count > 1) {
                            var newNode = new MutableIfStatementAst();
                            for (int i = 1; i < node.Clauses.Count; i++) newNode.Clauses.Add(node.Clauses[i]);
                            newNode.ElseClause = node.ElseClause;
                            return newNode;
                        } else if (node.ElseClause != null) {
                            return node.ElseClause;
                        } else {
                            return new MutableStatementBlockAst();
                        }
                    }
                }
            }
            return null;
        }

        private string GetCommandName(object node) {
             if (node is MutableCommandAst cmd && cmd.CommandElements.Count > 0) {
                 var first = cmd.CommandElements[0];
                 if (first is MutableStringConstantExpressionAst s) return s.Value;
             }
             return null;
        }

        private string GetVarName(object node) {
            if (node is MutableVariableExpressionAst ve) return ve.VariablePath;
            return null;
        }

        private object TryGetConstantValue(object node) {
            if (node == null) return null;
            if (node is MutablePipelineAst pipe) {
                if (pipe.PipelineElements.Count == 1) return TryGetConstantValue(pipe.PipelineElements[0]);
                return null;
            }
            if (node is MutableParenExpressionAst paren) {
                return TryGetConstantValue(paren.Pipeline);
            }
            if (node is MutableConvertExpressionAst conv) {
                var typeName = conv.Type.TypeName;
                if (string.Equals(typeName, "char", StringComparison.OrdinalIgnoreCase) || 
                    string.Equals(typeName, "System.Char", StringComparison.OrdinalIgnoreCase)) {
                    var val = TryGetConstantValue(conv.Child);
                    if (val is int i) return (char)i;
                }
                return null;
            }
            if (node is MutableTypeExpressionAst te) {
                try {
                     var t = Type.GetType(te.TypeName);
                     if (t != null) return t;
                     foreach(var asm in AppDomain.CurrentDomain.GetAssemblies()) {
                         t = asm.GetType(te.TypeName);
                         if (t != null) return t;
                     }
                } catch {}
                return null;
            }
            if (node is MutableCommandExpressionAst ce) return TryGetConstantValue(ce.Expression);
            if (node is MutableConstantExpressionAst c) return c.Value;
            if (node is MutableStringConstantExpressionAst s) return s.Value;
            if (node is MutableArrayLiteralAst arr) {
                var list = new List<object>();
                foreach (var e in arr.Elements) {
                    var v = TryGetConstantValue(e);
                    if (v == null) return null;
                    list.Add(v);
                }
                return list.ToArray();
            }
            return null;
        }

        private object CreateConstantNode(object val) {
            if (val == null) {
                var n = new MutableConstantExpressionAst(); n.Value = null; return n;
            }
            if (val is string s) {
                 var n = new MutableStringConstantExpressionAst();
                 n.Value = s;
                 n.StringConstantType = StringConstantType.SingleQuoted;
                 return n;
            }
            if (val is char c) {
                 var cast = new MutableConvertExpressionAst();
                 var attr = new MutableAttributeAst();
                 attr.TypeName = "char";
                 cast.Type = attr;
                 var cn = new MutableConstantExpressionAst(); 
                 cn.Value = (int)c;
                 cast.Child = cn;
                 return cast;
            }
            if (val is byte[] bArr) {
                var arr = new MutableArrayLiteralAst();
                foreach (var b in bArr) {
                    var cn = new MutableConstantExpressionAst(); cn.Value = (int)b;
                    arr.Elements.Add(cn);
                }
                var paren = new MutableParenExpressionAst();
                paren.Pipeline = arr;
                return paren;
            }
            if (val is IEnumerable enumerable) {
                 var arr = new MutableArrayLiteralAst();
                 foreach (var item in enumerable) {
                     var node = CreateConstantNode(item);
                     if (node is MutableExpressionAst expr) arr.Elements.Add(expr);
                 }
                 var paren = new MutableParenExpressionAst();
                 paren.Pipeline = arr;
                 return paren;
            }
            if (val is Type t) {
                var te = new MutableTypeExpressionAst();
                te.TypeName = t.FullName;
                return te;
            }
            if (val.GetType().IsPrimitive || val is decimal || val is DateTime || val is TimeSpan || val is Guid) {
                var nc = new MutableConstantExpressionAst(); nc.Value = val; return nc;
            }
            return null;
        }

        private object FoldBinary(MutableBinaryExpressionAst bin) {
            var l = TryGetConstantValue(bin.Left);
            var r = TryGetConstantValue(bin.Right);
            if (l != null && r != null) {
                try {
                    object res = null;
                    string op = bin.Operator.ToString();

                    if (op == "Plus" && (l is string || r is string)) {
                        res = l.ToString() + r.ToString();
                    }
                    else if (op == "Multiply" && (l is string s && r is int count)) {
                         res = String.Concat(System.Linq.Enumerable.Repeat(s, count));
                    }
                    else if (op == "Format") {
                        try {
                            if (r is object[] arr) {
                                res = String.Format(null, l.ToString(), arr);
                            } else {
                                res = String.Format(null, l.ToString(), r);
                            }
                        } catch {}
                    }
                    else if (op == "Join") {
                         if (l is IEnumerable && !(l is string)) {
                             var list = new List<string>();
                             foreach(var item in (IEnumerable)l) list.Add(item != null ? item.ToString() : "");
                             res = String.Join(r.ToString(), list.ToArray());
                         } else {
                             res = l.ToString();
                         }
                    }
                    else {
                        if (IsNumeric(l) && IsNumeric(r)) {
                            try {
                                int iL = Convert.ToInt32(l);
                                int iR = Convert.ToInt32(r);
                                switch (op) {
                                    case "Plus": res = iL + iR; break;
                                    case "Minus": res = iL - iR; break;
                                    case "Multiply": res = iL * iR; break;
                                    case "Divide": if (iR != 0) res = iL / iR; break;
                                }
                            } catch {
                                double dL = Convert.ToDouble(l);
                                double dR = Convert.ToDouble(r);
                                switch (op) {
                                    case "Plus": res = dL + dR; break;
                                    case "Minus": res = dL - dR; break;
                                    case "Multiply": res = dL * dR; break;
                                    case "Divide": if (dR != 0) res = dL / dR; break;
                                }
                            }
                        }
                    }

                    if (res != null) return CreateConstantNode(res);
                } catch {}
            }
            return null;
        }

        private bool IsNumeric(object o) {
            return o is int || o is long || o is double || o is float || o is decimal || o is byte || o is short || o is char;
        }

        private object TryEvaluateIntCharPipeline(MutablePipelineAst node) {
            if (node.PipelineElements.Count != 2) return null;
            
            var inputVal = TryGetConstantValue(node.PipelineElements[0]);
            if (inputVal == null || !(inputVal is IEnumerable) || (inputVal is string)) return null;
            
            var cmd = node.PipelineElements[1] as MutableCommandAst;
            if (cmd == null) return null;

            var cmdName = GetCommandName(cmd);
            if (cmdName != "%" && cmdName != "ForEach-Object") return null;

            MutableScriptBlockAst sb = null;
            foreach (var e in cmd.CommandElements) {
                if (e is MutableScriptBlockExpressionAst sbe) { sb = sbe.ScriptBlock; break; }
            }
            if (sb == null) return null;

            string sbCode = AstSourceCodeGenerator.ConvertToSourceCode(sb);
            if (System.Text.RegularExpressions.Regex.IsMatch(sbCode, @"(?i)[\[]char[\]][\s]*[[][\s]*[_$]")) {
                try {
                    StringBuilder charSb = new StringBuilder();
                    foreach (var i in (IEnumerable)inputVal) {
                        int val = Convert.ToInt32(i);
                        charSb.Append((char)val);
                    }
                    return CreateConstantNode(charSb.ToString());
                } catch {}
            }
            return null;
        }

        private object TryEvaluateCommand(MutableCommandAst cmd, DeobfuscatorContext ctx) {
            string cmdName = GetCommandName(cmd);
            if (cmdName == "New-Object") {
                string typeName = null;
                var args = new List<object>();
                
                for (int i = 1; i < cmd.CommandElements.Count; i++) {
                    var e = cmd.CommandElements[i];
                    if (e is MutableStringConstantExpressionAst sce && typeName == null) {
                        typeName = sce.Value;
                    } else if (e is MutableCommandParameterAst cp) {
                        if (cp.ParameterName == "TypeName") {
                             var v = TryGetConstantValue(cp.Argument);
                             if (v is string s) typeName = s;
                        }
                    } else {
                        var v = TryGetConstantValue(e);
                        if (v != null) args.Add(v);
                    }
                }

                if (typeName != null && IsTypeAllowed(typeName)) {
                    try {
                        Type t = null;
                        foreach(var asm in AppDomain.CurrentDomain.GetAssemblies()) {
                             t = asm.GetType(typeName) ?? asm.GetType("System."+typeName);
                             if (t != null) break;
                        }
                        if (t != null) {
                             object obj = Activator.CreateInstance(t, args.ToArray());
                             return CreateConstantNode(obj);
                        }
                    } catch {}
                }
            } else if (cmdName != null && ctx.Functions.ContainsKey(cmdName)) {
                bool isSafe = IsSafeToExecute(ctx.Functions[cmdName].Body, new HashSet<string>(StringComparer.OrdinalIgnoreCase), ctx);
                
                if (isSafe) {
                    var funcAst = ctx.Functions[cmdName];
                    var boundArgs = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
                    var positionalArgs = new List<object>();
                    var paramNames = new List<string>();
                    
                    if (funcAst.Parameters != null) {
                        foreach (var p in funcAst.Parameters) paramNames.Add(p.Name.VariablePath);
                    }
                    // Also check ScriptBlock ParamBlock
                    if (funcAst.Body.ParamBlock != null) {
                         foreach(var p in funcAst.Body.ParamBlock.Parameters) paramNames.Add(p.Name.VariablePath);
                    }

                    bool argsSafe = true;
                    for (int i = 1; i < cmd.CommandElements.Count; i++) {
                        var e = cmd.CommandElements[i];
                        if (e is MutableCommandParameterAst cp) {
                            string pName = cp.ParameterName;
                            object pValNode = cp.Argument;
                            if (pValNode == null && (i + 1 < cmd.CommandElements.Count)) {
                                pValNode = cmd.CommandElements[++i];
                            }
                            var v = TryGetConstantValue(pValNode);
                            if (v != null) boundArgs[pName] = v; else { argsSafe = false; break; }
                        } else {
                            var v = TryGetConstantValue(e);
                            if (v != null) positionalArgs.Add(v); else { argsSafe = false; break; }
                        }
                    }
                    
                    if (argsSafe) {
                        for(int i=0; i<positionalArgs.Count; i++) {
                            if (i < paramNames.Count) {
                                string pName = paramNames[i];
                                if (!boundArgs.ContainsKey(pName)) boundArgs[pName] = positionalArgs[i];
                            }
                        }

                        try {
                            string code = AstSourceCodeGenerator.ConvertToSourceCode(funcAst.Body);
                            using (var ps = PowerShell.Create()) {
                                ps.AddScript(code);
                                foreach(var kv in boundArgs) ps.AddParameter(kv.Key, kv.Value);
                                var results = ps.Invoke();
                                if (!ps.HadErrors && results.Count > 0) {
                                    return CreateConstantNode(results[0].BaseObject);
                                }
                            }
                        } catch {}
                    }
                }
            }
            return null;
        }

        private bool IsSafeToExecute(object node, HashSet<string> visitedFuncs, DeobfuscatorContext ctx) {
            if (node == null) return true;

            if (node is MutableScriptBlockAst sb) {
                return IsSafeToExecute(sb.BeginBlock, visitedFuncs, ctx) &&
                       IsSafeToExecute(sb.ProcessBlock, visitedFuncs, ctx) &&
                       IsSafeToExecute(sb.EndBlock, visitedFuncs, ctx) &&
                       IsSafeToExecute(sb.DynamicParamBlock, visitedFuncs, ctx);
            }
            if (node is MutableStatementBlockAst block) {
                foreach (var s in block.Statements) {
                    if (!IsSafeToExecute(s, visitedFuncs, ctx)) return false;
                }
                return true;
            }
            if (node is MutablePipelineAst pipe) {
                 foreach (var e in pipe.PipelineElements) {
                     if (!IsSafeToExecute(e, visitedFuncs, ctx)) return false;
                 }
                 return true;
            }
            if (node is MutableCommandExpressionAst ce) return IsSafeToExecute(ce.Expression, visitedFuncs, ctx);
            if (node is MutableExpressionAst expr) {
                if (expr is MutableConstantExpressionAst) return true;
                if (expr is MutableStringConstantExpressionAst) return true;
                if (expr is MutableVariableExpressionAst) return true;
                if (expr is MutableBinaryExpressionAst bin) return IsSafeToExecute(bin.Left, visitedFuncs, ctx) && IsSafeToExecute(bin.Right, visitedFuncs, ctx);
                if (expr is MutableUnaryExpressionAst un) return IsSafeToExecute(un.Child, visitedFuncs, ctx);
                if (expr is MutableParenExpressionAst p) return IsSafeToExecute(p.Pipeline, visitedFuncs, ctx);
                if (expr is MutableArrayLiteralAst arr) {
                    foreach (var e in arr.Elements) if (!IsSafeToExecute(e, visitedFuncs, ctx)) return false;
                    return true;
                }
                // Block MemberInvoke, MemberAccess, Indexing, etc.
                return false;
            }
            if (node is MutableAssignmentStatementAst assign) return IsSafeToExecute(assign.Right, visitedFuncs, ctx);
            if (node is MutableReturnStatementAst ret) return IsSafeToExecute(ret.Pipeline, visitedFuncs, ctx);
            if (node is MutableIfStatementAst ifStmt) {
                foreach(var c in ifStmt.Clauses) {
                    if (!IsSafeToExecute(c.Item1, visitedFuncs, ctx)) return false;
                    if (!IsSafeToExecute(c.Item2, visitedFuncs, ctx)) return false;
                }
                if (ifStmt.ElseClause != null) return IsSafeToExecute(ifStmt.ElseClause, visitedFuncs, ctx);
                return true;
            }
            if (node is MutableCommandAst cmd) {
                string name = GetCommandName(cmd);
                if (name != null && ctx.Functions.ContainsKey(name)) {
                    if (visitedFuncs.Contains(name)) return false; // Cycle
                    visitedFuncs.Add(name);
                    bool safe = IsSafeToExecute(ctx.Functions[name].Body, visitedFuncs, ctx);
                    visitedFuncs.Remove(name);
                    
                    if (safe) {
                         foreach(var e in cmd.CommandElements) {
                             if (!IsSafeToExecute(e, visitedFuncs, ctx)) return false;
                         }
                    }
                    return safe;
                }
                return false;
            }
            if (node is MutableCommandParameterAst cp) return IsSafeToExecute(cp.Argument, visitedFuncs, ctx);
            
            return false;
        }

        private object TryEvaluateInvoke(MutableInvokeMemberExpressionAst node, DeobfuscatorContext ctx) {
            object obj = null;
            string typeName = null;
            bool isStatic = node.Static;

            if (isStatic && node.Expression is MutableTypeExpressionAst te) {
                typeName = te.TypeName;
            } else {
                obj = TryGetConstantValue(node.Expression);
                if (obj == null && node.Expression is MutableVariableExpressionAst ve) {
                    obj = ctx.GetVar(ve.VariablePath);
                }
                if (obj is Type t) {
                    typeName = t.FullName;
                    isStatic = true;
                }
            }

            if (isStatic && typeName != null) {
                if (IsTypeAllowed(typeName)) {
                     var methodName = TryGetConstantValue(node.Member) as string;
                     if (methodName != null) {
                         var args = new List<object>();
                         foreach(var a in node.Arguments) {
                             var v = TryGetConstantValue(a);
                             if (v == null) return null;
                             args.Add(v);
                         }
                         try {
                             Type type = null;
                             foreach(var asm in AppDomain.CurrentDomain.GetAssemblies()) {
                                 type = asm.GetType(typeName) ?? asm.GetType("System."+typeName);
                                 if (type != null) break;
                             }
                             if (type != null) {
                                  if (methodName.Equals("Join", StringComparison.OrdinalIgnoreCase) && type.FullName == "System.String") {
                                       if (args.Count >= 2) {
                                           var sep = args[0] as string;
                                           if (args[1] is IEnumerable en) {
                                                var list = new List<string>();
                                                foreach(var item in en) list.Add(item != null ? item.ToString() : "");
                                                var joinRes = String.Join(sep, list.ToArray());
                                                return CreateConstantNode(joinRes);
                                           }
                                       }
                                  }
                                  
                                  var res = type.InvokeMember(methodName, BindingFlags.Public | BindingFlags.Static | BindingFlags.InvokeMethod | BindingFlags.FlattenHierarchy, null, null, args.ToArray());
                                  return CreateConstantNode(res);
                             }
                         } catch {}
                     }
                }
            } else if (obj != null && !isStatic) {
                var methodName = TryGetConstantValue(node.Member) as string;
                if (methodName != null) {
                     var args = new List<object>();
                     foreach(var a in node.Arguments) {
                         var v = TryGetConstantValue(a);
                         if (v == null) return null;
                         args.Add(v);
                     }
                     try {
                         var newArgs = new List<object>();
                         bool converted = false;
                         foreach(var a in args) {
                              if (a is object[] oa && oa.Length > 0 && (oa[0] is int || oa[0] is byte)) {
                                  try { 
                                      var bytes = new byte[oa.Length];
                                      for(int i=0; i<oa.Length; i++) bytes[i] = Convert.ToByte(oa[i]);
                                      newArgs.Add(bytes); 
                                      converted=true; 
                                      continue; 
                                  } catch {}
                              }
                              newArgs.Add(a);
                         }
                         
                         if (converted) {
                              try {
                                  var res = obj.GetType().InvokeMember(methodName, BindingFlags.Public | BindingFlags.Instance | BindingFlags.InvokeMethod, null, obj, newArgs.ToArray());
                                  return CreateConstantNode(res);
                              } catch {}
                         }
                         
                         var res2 = obj.GetType().InvokeMember(methodName, BindingFlags.Public | BindingFlags.Instance | BindingFlags.InvokeMethod, null, obj, args.ToArray());
                         return CreateConstantNode(res2);
                     } catch {}
                }
            }
            return null;
        }

        private object TryEvaluateMember(MutableMemberExpressionAst node, DeobfuscatorContext ctx) {
             if (node.Static && node.Expression is MutableTypeExpressionAst te) {
                 string typeName = te.TypeName;
                 if (IsTypeAllowed(typeName)) {
                     var memberName = TryGetConstantValue(node.Member) as string;
                     if (memberName != null) {
                         try {
                              Type type = null;
                              foreach(var asm in AppDomain.CurrentDomain.GetAssemblies()) {
                                  type = asm.GetType(typeName) ?? asm.GetType("System."+typeName);
                                  if (type != null) break;
                              }
                              if (type != null) {
                                  var prop = type.GetProperty(memberName, BindingFlags.Public | BindingFlags.Static);
                                  if (prop != null) return CreateConstantNode(prop.GetValue(null));
                                  var field = type.GetField(memberName, BindingFlags.Public | BindingFlags.Static);
                                  if (field != null) return CreateConstantNode(field.GetValue(null));
                              }
                         } catch {}
                     }
                 }
             } else {
                 object obj = TryGetConstantValue(node.Expression);
                 if (obj == null && node.Expression is MutableVariableExpressionAst ve) {
                     obj = ctx.GetVar(ve.VariablePath);
                 }
                 if (obj != null) {
                     var memberName = TryGetConstantValue(node.Member) as string;
                     if (memberName != null) {
                         try {
                              var prop = obj.GetType().GetProperty(memberName);
                              if (prop != null) return CreateConstantNode(prop.GetValue(obj));
                              var field = obj.GetType().GetField(memberName);
                              if (field != null) return CreateConstantNode(field.GetValue(obj));
                         } catch {}
                     }
                 }
             }
             return null;
        }

        private void TryEvaluateAssignmentToMember(MutableAssignmentStatementAst node, DeobfuscatorContext ctx) {
            if (node.Left is MutableMemberExpressionAst me) {
                var objVarName = GetVarName(me.Expression);
                if (objVarName != null && ctx.IsConstant(objVarName)) {
                    object obj = ctx.GetVar(objVarName);
                    var memberName = TryGetConstantValue(me.Member) as string;
                    object val = TryGetConstantValue(node.Right);
                    if (obj != null && memberName != null && val != null) {
                        try {
                            var prop = obj.GetType().GetProperty(memberName);
                            if (prop != null) { prop.SetValue(obj, val); return; }
                            var field = obj.GetType().GetField(memberName);
                            if (field != null) { field.SetValue(obj, val); return; }
                        } catch {}
                    }
                }
            }
        }

        private void RemoveDeadCode(MutableAst root) {
            var usedVars = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var usedFuncs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            FindUsedSymbols(root, usedVars, usedFuncs);
            PruneSymbols(root, usedVars, usedFuncs);
        }

        private void FindUsedSymbols(object node, HashSet<string> usedVars, HashSet<string> usedFuncs) {
            if (node == null) return;
            if (node is MutableAssignmentStatementAst assign) {
                FindUsedSymbols(assign.Right, usedVars, usedFuncs);
            } else if (node is MutableVariableExpressionAst ve) {
                usedVars.Add(ve.VariablePath);
            } else if (node is MutableCommandAst cmd) {
                var name = GetCommandName(cmd);
                if (name != null) usedFuncs.Add(name);
                foreach (var e in cmd.CommandElements) FindUsedSymbols(e, usedVars, usedFuncs);
            } else {
                foreach (var prop in node.GetType().GetProperties()) {
                     if (prop.Name == "NodeType") continue;
                     object val = null;
                     try { val = prop.GetValue(node); } catch { continue; }
                     if (val == null) continue;
                     
                     if (val is MutableAst) FindUsedSymbols(val, usedVars, usedFuncs);
                     else if (val is IEnumerable en && !(val is string)) {
                         foreach (var item in en) {
                             if (item is MutableAst) FindUsedSymbols(item, usedVars, usedFuncs);
                         }
                     }
                }
            }
        }

        private void PruneSymbols(object node, HashSet<string> usedVars, HashSet<string> usedFuncs) {
            if (node == null) return;
            
            IList stmts = null;
            if (node is MutableStatementBlockAst sb) stmts = sb.Statements;
            else if (node is MutableScriptBlockAst scb) { PruneSymbols(scb.EndBlock, usedVars, usedFuncs); return; }
            
            if (stmts != null) {
                for (int i = stmts.Count - 1; i >= 0; i--) {
                    var s = stmts[i];
                    PruneSymbols(s, usedVars, usedFuncs);
                    
                    if (s is MutableAssignmentStatementAst assign) {
                        var name = GetVarName(assign.Left);
                        if (name != null && !usedVars.Contains(name)) {
                            stmts.RemoveAt(i);
                            continue;
                        }
                    } else if (s is MutableFunctionDefinitionAst fd) {
                        if (!usedFuncs.Contains(fd.Name)) {
                            stmts.RemoveAt(i);
                            continue;
                        }
                    } else if (s is MutableForStatementAst forStmt) {
                        if (forStmt.Body.Statements.Count == 0) { stmts.RemoveAt(i); continue; }
                    } else if (s is MutableForEachStatementAst forEach) {
                        if (forEach.Body.Statements.Count == 0) { stmts.RemoveAt(i); continue; }
                    } else if (s is MutableTryStatementAst tryStmt) {
                        if (tryStmt.Body.Statements.Count == 0) { stmts.RemoveAt(i); continue; }
                    } else if (s is MutableIfStatementAst ifStmt) {
                         if (ifStmt.ElseClause != null && ifStmt.ElseClause.Statements.Count == 0) {
                             ifStmt.ElseClause = null;
                         }
                         bool anyBody = false;
                         if (ifStmt.ElseClause != null) anyBody = true;
                         else {
                             foreach(var c in ifStmt.Clauses) {
                                 if (c.Item2 is MutableStatementBlockAst clauseBody && clauseBody.Statements.Count > 0) { anyBody = true; break; }
                             }
                         }
                         if (!anyBody) { stmts.RemoveAt(i); continue; }
                    }
                }
            } else {
                foreach (var prop in node.GetType().GetProperties()) {
                     if (prop.Name == "NodeType") continue;
                     object val = null;
                     try { val = prop.GetValue(node); } catch { continue; }
                     if (val == null) continue;
                     
                     if (val is MutableAst) PruneSymbols(val, usedVars, usedFuncs);
                     else if (val is IEnumerable en && !(val is string)) {
                         foreach (var item in en) {
                             if (item is MutableAst) PruneSymbols(item, usedVars, usedFuncs);
                         }
                     }
                }
            }
        }
    }
}
'@

Add-Type -TypeDefinition $csharpSource -ReferencedAssemblies @(
    'System.Management.Automation',
    'System.Core',
    'System.Collections',
    'System.Collections.Concurrent',
    'System.Text.RegularExpressions',
    'System.Linq'
) -Language CSharp

function Deobfuscate-Script {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) {
        Write-Error "File not found: $FilePath"
        return
    }

    $absPath = Convert-Path $FilePath
    $ScriptContent = Get-Content -LiteralPath $absPath -Raw -Encoding UTF8
    
    $deob = [DeobfuscatorKit.Deobfuscator]::new()
    $deob.DeobfuscateAndSave($ScriptContent, $absPath)
    
    Write-Host "Deobfuscation complete. Output files saved in $(Split-Path $absPath)"
}
