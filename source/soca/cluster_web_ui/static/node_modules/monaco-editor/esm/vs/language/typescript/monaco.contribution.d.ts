import IEvent = monaco.IEvent;
import IDisposable = monaco.IDisposable;
export interface IExtraLib {
    content: string;
    version: number;
}
export interface IExtraLibs {
    [path: string]: IExtraLib;
}
export declare class LanguageServiceDefaultsImpl implements monaco.languages.typescript.LanguageServiceDefaults {
    private _onDidChange;
    private _onDidExtraLibsChange;
    private _extraLibs;
    private _eagerModelSync;
    private _compilerOptions;
    private _diagnosticsOptions;
    private _onDidExtraLibsChangeTimeout;
    constructor(compilerOptions: monaco.languages.typescript.CompilerOptions, diagnosticsOptions: monaco.languages.typescript.DiagnosticsOptions);
    get onDidChange(): IEvent<void>;
    get onDidExtraLibsChange(): IEvent<void>;
    getExtraLibs(): IExtraLibs;
    addExtraLib(content: string, _filePath?: string): IDisposable;
    setExtraLibs(libs: {
        content: string;
        filePath?: string;
    }[]): void;
    private _fireOnDidExtraLibsChangeSoon;
    getCompilerOptions(): monaco.languages.typescript.CompilerOptions;
    setCompilerOptions(options: monaco.languages.typescript.CompilerOptions): void;
    getDiagnosticsOptions(): monaco.languages.typescript.DiagnosticsOptions;
    setDiagnosticsOptions(options: monaco.languages.typescript.DiagnosticsOptions): void;
    setMaximumWorkerIdleTime(value: number): void;
    setEagerModelSync(value: boolean): void;
    getEagerModelSync(): boolean;
}
