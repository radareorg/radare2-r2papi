program Json;

uses fpjson, jsonparser;

Function r2cmd(C: string) : string; external name 'r2cmd';

var
  s: string;
  j: TJSONData;

begin
  writeln ('Hello, world.');
  s := r2cmd('ij');
  j := TJSON.parse(s);
  writeln (s);
  writeln (j);
end.
