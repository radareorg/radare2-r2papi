/**
 * Generic interface to interact with radare2, abstracts the access to the associated
 * instance of the tool, which could be native via rlang or remote via pipes or tcp/http.
 *
 * @typedef R2Pipe
 */
export interface R2Pipe {
    /**
         * Run a command in the associated instance of radare2
         *
         * @param {string} command to be executed inside radare2.
         * @returns {string} The output of the command execution
         */
    cmd(cmd: string): string;
    /**
         * Run a radare2 command in a different address. Same as `.cmd(x + '@ ' + a)`
         *
         * @param {string} cmd to be executed inside radare2.
         * @returns {string} The output of the command execution
         */
    cmdAt(cmd: string): string;
    /**
         * Run a radare2 command expecting the output to be JSON
         *
         * @param {string} cmd to be executed inside radare2.
         * @returns {object} the JSON decoded object from the output of the command
         */
    cmdj(cmd: string): any;
    /**
         * Call a radare2 command. This is similar to `R2Pipe.cmd`, but skips all the command parsing rules,
     * which is safer and faster but you cannot use any special modifier like `@`, `~`, ...
     *
     * See R2Pipe.callAt() to call a command on a different address
         *
         * @param {string} cmd to be executed inside radare2. The given command should end with `j`
         * @returns {object} the JSON decoded object from the output of the command
         */
    call(cmd: string): string;
    /**
         * Call a radare2 command in a different address
         *
         * @param {string} cmd to be executed inside radare2.
         * @param {NativePointer|string|number} where to seek to execute this command (previous offset is restored after executing it)
         * @returns {string} the string containing the output of the command
         */
    callAt(cmd: string, at: string | number | any): string;
    /**
         * Same as cmdj but using .call which avoids command injection problems
         *
         * @param {string} cmd to be executed inside radare2.
         * @returns {string} the string containing the output of the command
         */
    callj(cmd: string): any;
    /**
         * Same as cmdj but using .call which avoids command injection problems
         *
         * @param {string} cmd to be executed inside radare2.
         * @returns {object} the JSON decoded object from the output of the command
         */
    log(msg: string): string;
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
 * A global instance of R2Pipe associated with the current instance of radare2
 *
 * @type {R2Pipe}
 */
export declare var r2: R2Pipe;
