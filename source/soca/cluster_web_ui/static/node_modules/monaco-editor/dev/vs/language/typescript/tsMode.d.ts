import { TypeScriptWorker } from './tsWorker';
import { LanguageServiceDefaultsImpl } from './monaco.contribution';
import Uri = monaco.Uri;
export declare function setupTypeScript(defaults: LanguageServiceDefaultsImpl): void;
export declare function setupJavaScript(defaults: LanguageServiceDefaultsImpl): void;
export declare function getJavaScriptWorker(): Promise<(first: Uri, ...more: Uri[]) => Promise<TypeScriptWorker>>;
export declare function getTypeScriptWorker(): Promise<(first: Uri, ...more: Uri[]) => Promise<TypeScriptWorker>>;
