import { LanguageServiceDefaultsImpl } from './monaco.contribution';
import * as ts from './lib/typescriptServices';
import { TypeScriptWorker } from './tsWorker';
import Uri = monaco.Uri;
import Position = monaco.Position;
import Range = monaco.Range;
import CancellationToken = monaco.CancellationToken;
export declare function flattenDiagnosticMessageText(diag: string | ts.DiagnosticMessageChain | undefined, newLine: string, indent?: number): string;
export declare abstract class Adapter {
    protected _worker: (first: Uri, ...more: Uri[]) => Promise<TypeScriptWorker>;
    constructor(_worker: (first: Uri, ...more: Uri[]) => Promise<TypeScriptWorker>);
    protected _textSpanToRange(model: monaco.editor.ITextModel, span: ts.TextSpan): monaco.IRange;
}
export declare class DiagnosticsAdapter extends Adapter {
    private _defaults;
    private _selector;
    private _disposables;
    private _listener;
    constructor(_defaults: LanguageServiceDefaultsImpl, _selector: string, worker: (first: Uri, ...more: Uri[]) => Promise<TypeScriptWorker>);
    dispose(): void;
    private _doValidate;
    private _convertDiagnostics;
    private _convertRelatedInformation;
    private _tsDiagnosticCategoryToMarkerSeverity;
}
export declare class SuggestAdapter extends Adapter implements monaco.languages.CompletionItemProvider {
    get triggerCharacters(): string[];
    provideCompletionItems(model: monaco.editor.ITextModel, position: Position, _context: monaco.languages.CompletionContext, token: CancellationToken): Promise<monaco.languages.CompletionList | undefined>;
    resolveCompletionItem(model: monaco.editor.ITextModel, _position: Position, item: monaco.languages.CompletionItem, token: CancellationToken): Promise<monaco.languages.CompletionItem>;
    private static convertKind;
}
export declare class SignatureHelpAdapter extends Adapter implements monaco.languages.SignatureHelpProvider {
    signatureHelpTriggerCharacters: string[];
    provideSignatureHelp(model: monaco.editor.ITextModel, position: Position, token: CancellationToken): Promise<monaco.languages.SignatureHelpResult | undefined>;
}
export declare class QuickInfoAdapter extends Adapter implements monaco.languages.HoverProvider {
    provideHover(model: monaco.editor.ITextModel, position: Position, token: CancellationToken): Promise<monaco.languages.Hover | undefined>;
}
export declare class OccurrencesAdapter extends Adapter implements monaco.languages.DocumentHighlightProvider {
    provideDocumentHighlights(model: monaco.editor.ITextModel, position: Position, token: CancellationToken): Promise<monaco.languages.DocumentHighlight[] | undefined>;
}
export declare class DefinitionAdapter extends Adapter {
    provideDefinition(model: monaco.editor.ITextModel, position: Position, token: CancellationToken): Promise<monaco.languages.Definition | undefined>;
}
export declare class ReferenceAdapter extends Adapter implements monaco.languages.ReferenceProvider {
    provideReferences(model: monaco.editor.ITextModel, position: Position, context: monaco.languages.ReferenceContext, token: CancellationToken): Promise<monaco.languages.Location[] | undefined>;
}
export declare class OutlineAdapter extends Adapter implements monaco.languages.DocumentSymbolProvider {
    provideDocumentSymbols(model: monaco.editor.ITextModel, token: CancellationToken): Promise<monaco.languages.DocumentSymbol[] | undefined>;
}
export declare class Kind {
    static unknown: string;
    static keyword: string;
    static script: string;
    static module: string;
    static class: string;
    static interface: string;
    static type: string;
    static enum: string;
    static variable: string;
    static localVariable: string;
    static function: string;
    static localFunction: string;
    static memberFunction: string;
    static memberGetAccessor: string;
    static memberSetAccessor: string;
    static memberVariable: string;
    static constructorImplementation: string;
    static callSignature: string;
    static indexSignature: string;
    static constructSignature: string;
    static parameter: string;
    static typeParameter: string;
    static primitiveType: string;
    static label: string;
    static alias: string;
    static const: string;
    static let: string;
    static warning: string;
}
export declare abstract class FormatHelper extends Adapter {
    protected static _convertOptions(options: monaco.languages.FormattingOptions): ts.FormatCodeOptions;
    protected _convertTextChanges(model: monaco.editor.ITextModel, change: ts.TextChange): monaco.languages.TextEdit;
}
export declare class FormatAdapter extends FormatHelper implements monaco.languages.DocumentRangeFormattingEditProvider {
    provideDocumentRangeFormattingEdits(model: monaco.editor.ITextModel, range: Range, options: monaco.languages.FormattingOptions, token: CancellationToken): Promise<monaco.languages.TextEdit[] | undefined>;
}
export declare class FormatOnTypeAdapter extends FormatHelper implements monaco.languages.OnTypeFormattingEditProvider {
    get autoFormatTriggerCharacters(): string[];
    provideOnTypeFormattingEdits(model: monaco.editor.ITextModel, position: Position, ch: string, options: monaco.languages.FormattingOptions, token: CancellationToken): Promise<monaco.languages.TextEdit[] | undefined>;
}
export declare class CodeActionAdaptor extends FormatHelper implements monaco.languages.CodeActionProvider {
    provideCodeActions(model: monaco.editor.ITextModel, range: Range, context: monaco.languages.CodeActionContext, token: CancellationToken): Promise<monaco.languages.CodeActionList | undefined>;
    private _tsCodeFixActionToMonacoCodeAction;
}
export declare class RenameAdapter extends Adapter implements monaco.languages.RenameProvider {
    provideRenameEdits(model: monaco.editor.ITextModel, position: Position, newName: string, token: CancellationToken): Promise<monaco.languages.WorkspaceEdit & monaco.languages.Rejection | undefined>;
}
