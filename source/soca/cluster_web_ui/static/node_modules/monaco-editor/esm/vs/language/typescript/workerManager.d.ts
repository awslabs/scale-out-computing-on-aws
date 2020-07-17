import { LanguageServiceDefaultsImpl } from './monaco.contribution';
import { TypeScriptWorker } from './tsWorker';
import Uri = monaco.Uri;
export declare class WorkerManager {
    private _modeId;
    private _defaults;
    private _configChangeListener;
    private _updateExtraLibsToken;
    private _extraLibsChangeListener;
    private _worker;
    private _client;
    constructor(modeId: string, defaults: LanguageServiceDefaultsImpl);
    private _stopWorker;
    dispose(): void;
    private _updateExtraLibs;
    private _getClient;
    getLanguageServiceWorker(...resources: Uri[]): Promise<TypeScriptWorker>;
}
