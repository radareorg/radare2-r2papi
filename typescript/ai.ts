import { R, Module, Process, Thread } from "./r2papi.js"
import { r2, R2Pipe } from "./r2pipe.js";

export class R2AI {
	available : boolean = false;
	model : string = "";
	constructor (num?: number, model?: string) {
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
			throw new Error ("ERROR: r2ai is not installed");
		}
	}
	reset() {
		if (this.available) {
			r2.call('r2ai -R')
		}
	}
	setRole(msg: string) {
		if (this.available) {
			r2.call(`r2ai -r ${msg}`)
		}
	}
	setModel(modelName: string) {
		if (this.available) {
			r2.call(`r2ai -m ${this.model}`)
		}
	}
	getModel() : string {
		if (this.available) {
			return r2.call("r2ai -m").trim();
		}
		return this.model;
	}
	listModels() : string[] {
		if (this.available) {
			return r2.call("r2ai -M").trim().split(/\n/g);
		}
		return [];
	}
	query(msg: string) : string {
		if (!this.available || msg == '') {
			return '';
		}
		const fmsg = msg.trim().replace(/\n/g, '.');
		return r2.call(`r2ai ${fmsg}`).trim();
	}
}


