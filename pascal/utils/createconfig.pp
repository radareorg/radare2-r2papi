program createconfig;

{$mode objfpc}
{$h+}

uses sysutils;

Var
  F : Text;
  CfgFile : String;
  BaseDir : String;

Procedure AddLn(S : String);

begin
  Writeln(F,S);
end;
  
begin
  if ParamCount<>2 then 
    begin
    Writeln('Usage ',ParamStr(0),' cfgfile basedir');
    Writeln('Basedir relative to cfgfile');
    Halt(1);
    end;
  CfgFile:=Paramstr(1);
  BaseDir:=ParamStr(2);  
  if not ForceDirectories(ExtractFilePath(CfgFile)) then
    begin
    Writeln(StdErr,'Could not create destination directory ',ExtractFilePath(CfgFile));
    Halt(2);
    end;
  Assign(F,CfgFile);
  try
    Rewrite(F);  
  except
    On E : exception do
      begin
      Writeln(StdErr,'Could not create config file ',CfgFile,' : ',E.Message);
      Halt(3);
      end;
  end;
  
  Addln('#');
  Addln('# Minimal config file for pas2js compiler');
  Addln('#');
  Addln('');
  Addln('# -d is the same as #DEFINE');
  Addln('# -u is the same as #UNDEF');
  Addln('');
  Addln('# Write always a nice logo ;)');
  Addln('-l');
  Addln('');
  Addln('# Display Warnings, Notes and Hints');
  Addln('-vwnh');
  Addln('# If you don''t want so much verbosity use');
  Addln('#-vw');
  Addln('');
  Addln('-Fu$CfgDir/'+BASEDIR+'/packages/*');
  Addln('');
  Addln('#IFDEF nodejs');
  Addln('-Jirtl.js');
  Addln('#ENDIF');
  Addln('');
  Addln('# Put all generated JavaScript into one js file:');
  Addln('-Jc');
  Addln('');
  Addln('# end.');
  Close(F);
end.
