export class R2PipeAsyncFromSync {
    r2p: R2Pipe;
    constructor(r2p: R2Pipe) {
        this.r2p = r2p;
    }
    /**
     * Run a command in the associated instance of radare2 and return the output as a string
     *
     * @param {string} command to be executed inside radare2.
     * @returns {string} The output of the command execution
     */
    async cmd(command: string): Promise<string> {
        return this.r2p.cmd(command);
    }
    async cmdAt(
        command: string,
        address: number | string | any
    ): Promise<string> {
        return this.r2p.cmdAt(command, address);
    }
    async cmdj(cmd: string): Promise<any> {
        return this.r2p.cmdj(cmd);
    }
    async call(command: string): Promise<string> {
        return this.r2p.call(command);
    }
    async callj(cmd: string): Promise<any> {
        return this.r2p.cmdj(cmd);
    }
    async callAt(
        command: string,
        address: number | string | any
    ): Promise<string> {
        return this.r2p.cmdAt(command, address);
    }
    async log(msg: string) {
        return this.r2p.log(msg);
    }
    async plugin(type: string, maker: any): Promise<boolean> {
        return this.r2p.plugin(type, maker);
    }
    async unload(type: string, name: string): Promise<boolean> {
        return this.r2p.unload(type, name);
    }
}

export function newAsyncR2PipeFromSync(r2p: R2Pipe): R2PipeAsync {
    const asyncR2Pipe = new R2PipeAsyncFromSync(r2p);
    return asyncR2Pipe as R2PipeAsync;
}

/**
 * Generic interface to interact with radare2, abstracts the access to the associated
 * instance of the tool, which could be native via rlang or remote via pipes or tcp/http.
 *
 * @typedef R2Pipe
 */
export interface R2Pipe {
    /**
     * Run a command in the associated instance of radare2 and return the output as a string
     *
     * @param {string} command to be executed inside radare2.
     * @returns {string} The output of the command execution
     */
    cmd(cmd: string): string;

    /**
     * Run a radare2 command in a different address. Same as `.cmd(x + '@ ' + a)`
     *
     * @param {string} command to be executed inside radare2.
     * @param {number|string|NativePointer} command to be executed inside radare2.
     * @returns {string} The output of the command execution
     */
    cmdAt(cmd: string, address: number | string | any): string;

    /**
     * Run a radare2 command expecting the output to be JSON
     *
     * @param {string} command to be executed inside radare2. The given command should end with `j`
     * @returns {object} the JSON decoded object from the output of the command
     */
    cmdj(cmd: string): any;

    /**
     * Call a radare2 command. This is similar to `R2Pipe.cmd`, but skips all the command parsing rules,
     * which is safer and faster but you cannot use any special modifier like `@`, `~`, ...
     *
     * See R2Pipe.callAt() to call a command on a different address
     *
     * @param {string} command to be executed inside radare2. The given command should end with `j`
     * @returns {object} the JSON decoded object from the output of the command
     */
    call(cmd: string): string;

    /**
     * Call a radare2 command in a different address
     *
     * @param {string} command to be executed inside radare2. The given command should end with `j`
     * @param {NativePointer|string|number} where to seek to execute this command (previous offset is restored after executing it)
     * @returns {string} the string containing the output of the command
     */
    callAt(cmd: string, address: string | number | any): string;

    /**
     * Same as cmdj but using .call which avoids command injection problems
     *
     * @param {string} command to be executed inside radare2. The given command should end with `j`
     * @returns {object} the JSON decoded object from the command output
     */
    callj(cmd: string): any;

    /**
     * Log a string to the associated console. This is used internally by `console.log` in some implementations.
     *
     * @param {string} text to be displayed
     */
    log(msg: string): void;

    /**
     * Instantiate a new radare2 plugin with the given type and constructor method.
     *
     * @param {string} type of plugin ("core", "io", "arch", ...)
     * @param {string} function that returns the plugin definition
     * @returns {boolean} true if successful
     */
    plugin(type: string, maker: any): boolean;

    /**
     * Unload the plugin associated with a `type` and a `name`.
     *
     * @param {string} type of plugin ("core", "io", "arch", ...)
     * @param {string} name of the plugin
     * @returns {boolean} true if successful
     */
    unload(type: string, name: string): boolean;
}

/**
 * Generic interface to interact with radare2, abstracts the access to the associated
 * instance of the tool, which could be native via rlang or remote via pipes or tcp/http.
 *
 * @typedef R2PipeAsync
 */
export interface R2PipeAsync {
    /**
     * Run a command in the associated instance of radare2
     *
     * @param {string} command to be executed inside radare2.
     * @returns {string} The output of the command execution
     */
    cmd(cmd: string): Promise<string>;

    /**
     * Run a radare2 command in a different address. Same as `.cmd(x + '@ ' + a)`
     *
     * @param {string} command to be executed inside radare2.
     * @param {number|string|NativePointer} command to be executed inside radare2.
     * @returns {string} The output of the command execution
     */
    cmdAt(cmd: string, address: number | string | any): Promise<string>;

    /**
     * Run a radare2 command expecting the output to be JSON
     *
     * @param {string} command to be executed inside radare2. The given command should end with `j`
     * @returns {object} the JSON decoded object from the output of the command
     */
    cmdj(cmd: string): Promise<any>;

    /**
     * Call a radare2 command. This is similar to `R2Pipe.cmd`, but skips all the command parsing rules,
     * which is safer and faster but you cannot use any special modifier like `@`, `~`, ...
     *
     * See R2Pipe.callAt() to call a command on a different address
     *
     * @param {string} command to be executed inside radare2. The given command should end with `j`
     * @returns {object} the JSON decoded object from the output of the command
     */
    call(cmd: string): Promise<string>;

    /**
     * Call a radare2 command in a different address
     *
     * @param {string} command to be executed inside radare2. The given command should end with `j`
     * @param {NativePointer|string|number} where to seek to execute this command (previous offset is restored after executing it)
     * @returns {string} the string containing the output of the command
     */
    callAt(cmd: string, address: string | number | any): Promise<string>;

    /**
     * Same as cmdj but using .call which avoids command injection problems
     *
     * @param {string} command to be executed inside radare2. The given command should end with `j`
     * @returns {object} the JSON decoded object from the command output
     */
    callj(cmd: string): Promise<any>;

    /**
     * Log a string to the associated console. This is used internally by `console.log` in some implementations.
     *
     * @param {string} text to be displayed
     */
    log(msg: string): void;

    /**
     * Instantiate a new radare2 plugin with the given type and constructor method.
     *
     * @param {string} type of plugin ("core", "io", "arch", ...)
     * @param {string} function that returns the plugin definition
     * @returns {boolean} true if successful
     */
    plugin(type: string, maker: any): Promise<boolean>;

    /**
     * Unload the plugin associated with a `type` and a `name`.
     *
     * @param {string} type of plugin ("core", "io", "arch", ...)
     * @param {string} name of the plugin
     * @returns {boolean} true if successful
     */
    unload(type: string, name: string): Promise<boolean>;
}

/**
 * A global instance of R2Pipe associated with the current instance of radare2
 *
 * @type {R2PipeSync}
 */
export declare const r2: R2Pipe;
