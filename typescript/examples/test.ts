import { R, R2Papi, NativePointer } from "../index";

namespace Main {
    const searchResults = R.searchString("lib");
    console.log(`Found ${searchResults.length} results`)
    for (let result of searchResults) {
	    const nullptr = new NativePointer(0);
	    console.log(nullptr.isNull());
	/*
        const text = new NativePointer(R, result.offset);
        console.log(result.offset, text); // .readCString());
	*/
    }
}
