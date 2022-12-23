program Hello;

Function r2cmd(C: string) : string; external name 'r2cmd';

var
  s: string;

begin
  writeln ('Hello, world.');
  s := r2cmd('?E Hello');
  writeln (s);
end.
