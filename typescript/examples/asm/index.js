//{{ifr2}}
import { main } from "./main.js";
import * as Instruction from "./rvcodecjs/core/Instruction.js";
main(Instruction);
//{{else}}
/*
import ("./main.js").then((main) => {
	import ("./rvcodecjs/core/Instruction.js").then((Instruction) => {
		console.log("jeje", Instruction);
		console.log("main", main.main);
		main.main(Instruction);
	});
});
*/
//{{endif}}
