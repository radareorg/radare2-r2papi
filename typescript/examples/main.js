// declare var Gmain: Function;
console.log("main");
if (!Gmain) {
    var Gmain = (r2, args) => { };
}
Gmain = function (r2, args) {
    console.log(Object.keys(args));
    const res = r2.cmd("x");
    console.log("Hello World", res);
};
console.log("pre");
Gmain(r2, []);
console.log("pos");
