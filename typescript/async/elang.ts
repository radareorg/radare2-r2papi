import { R2PipeAsync } from "./index";

// esil high level language - functional programming
//

export class EsilLang {
    [vars: string]: any;
    constructor() {
        this.vars = {};
    }
    set(obj: any, val: any) {
        this.vars[obj] = val;
    }
    fun(name: string, code: any[]) {
        this.vars[name] = code;
    }
    get(varname: string): any {
        if (varname in Object.keys(this.vars)) {
            return this.vars[varname];
        }
        this.vars[varname] = 0;
        return 0;
    }
    println(...args: any) {
        console.log(...args);
    }
    eval(code: string) {}
}

// basic elements: array, string,
// console.log("Hello Lang");
const el = new EsilLang();
const code = `[
]
`;

el.eval(code);
console.log("Hello `test()` World");

/*
   96,sp,-=,x28,sp,=[8],x27,sp,8,+,=[8]
   (96,sp,-=),(x28,sp,=[8]),(x27,(sp,8,+),=[8])

   (-=,sp,96),(=[8],sp,x28),(=[8],(+,8,sp),x27)
   (sp,-=, 96),(sp, =[8], x28),((+,8,sp), =[8], x27)

     (96, sp, -=),
     (x28, sp, =[8]),
     (x27, (sp, 8, +), =[8])

   set(poke, {
	args("nan", addr, value, size)
	r2(str('wx', size, ' ', value, ' @ ', addr))
	for (=(i,0), <= (i, 10), {
		println("Hello World")
		= (i, +(i, 1))
	})
   })

   set("main", "println(123)")
   main()

   set(sp, reg("sp"))
   label("bb4000")
   set(sp, -(sp, 96))
   poke(sp, x28, 8) // addr value size
   poke(+(sp, 8), x27, 8)
   if (eq (sp, bp), [
     goto("bb4000")
   ]
   set(pc, lr)


el.fun("main", [
  set("test", """
  [
	set("n", 0),
	label("repeat"),
	if (eq (arg("n"), 0),
		[ret(1)]
	),
	println("Hello World"),
	goto("repeat")
	ret(0)
  ),
  set("res", r2("x 32")),
  // $res = r2("x 32")
  if (eq (res, 0), [
	// if body when res == 0
  ]
""")
  test(),
  "test"(),
  123(),
  call("test"), // test(),
  'set("name", "John")', // '0x80480,x0,:='
  'println("Hello", get("name"))' // 
]);

*/
