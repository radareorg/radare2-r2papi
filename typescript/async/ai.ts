import { R, Module, Process, Thread } from "./r2papi.js"
import { r2, R2PipeAsync } from "./r2pipe.js";

/**
 * Class that interacts with the `r2ai` plugin (requires `rlang-python` and `r2i` r2pm packages to be installed).
 * Provides a way to script the interactions with different language models using javascript from inside radare2.
 * 
 * @typedef R2AI
 */
export class R2AI {
	/**
	 * Instance variable that informs if the `r2ai` plugin is loaded, must be true in order to use the rest of the methods of this class.
	 *
	 * @type {boolean}
	 */
	available: boolean = false;
	/**
	 * Name of the model instantiated to be used for the subsequent calls.
	 *
	 * @type {string}
	 */
	model: string = "";
	constructor(num?: number, model?: string) {
		this.available = r2.cmd('r2ai -h').trim() !== "";
		if (this.available) {
			if (num) {
				r2.call(`r2ai -n ${num}`)
			}
			// r2.call('r2ai -e DEBUG=1')
			if (model) {
				this.model = model;
			}
		} else {
			throw new Error("ERROR: r2ai is not installed");
		}
	}
	/**
	 * Reset conversation messages
	 */
	reset() {
		if (this.available) {
			r2.call('r2ai -R')
		}
	}
	/**
	 * Set the role (system prompt) message for the language model to obey.
	 *
	 * @param {string} text containing the system prompt
	 * @returns {boolean} true if successful
	 */
	setRole(msg: string): boolean {
		if (this.available) {
			r2.call(`r2ai -r ${msg}`);
			return true;
		}
		return false;
	}
	/**
	 * Set the Model name or path to the GGUF file to use.
	 *
	 * @param {string} model name or path to GGUF file
	 * @returns {boolean} true if successful
	 */
	setModel(modelName: string): boolean {
		if (this.available) {
			r2.call(`r2ai -m ${this.model}`)
			return true;
		}
		return false;
	}
	/**
	 * Get the current selected model name.
	 *
	 * @returns {boolean} model name
	 */
	getModel(): string {
		if (this.available) {
			this.model = r2.call("r2ai -m").trim();
		}
		return this.model;
	}
	/**
	 * Get a list of suggestions for model names to use.
	 *
	 * @returns {string[]} array of strings containing the model names known to work
	 */
	listModels(): string[] {
		if (this.available) {
			return r2.call("r2ai -M").replace(/-m /, "").trim().split(/\n/g).filter((x) => x.indexOf(":") !== -1);
		}
		return [];
	}
	/**
	 * Send message to the language model to be appended to the current conversation (see `.reset()`)
	 *
	 * @param {string} text sent from the user to the language model
	 * @returns {string} response from the language model
	 */
	query(msg: string): string {
		if (!this.available || msg == '') {
			return '';
		}
		const fmsg = msg.trim().replace(/\n/g, '.');
		return r2.call(`r2ai ${fmsg}`).trim();
	}
}
