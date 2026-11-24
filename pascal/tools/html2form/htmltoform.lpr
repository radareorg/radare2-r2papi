{
    Copyright (c) 2020 by Michael Van Canneyt michael@freepascal.org
    This file is part of the pas2js toolset

    HTML to pascal code converter program

    See the file COPYING.FPC, included in this distribution,
    for details about the copyright.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

 **********************************************************************}

program htmltoform;

uses sysutils, classes, fpjson, jsonparser, sax,sax_html, custapp, formgen, webcoreformgen;

Type

  { THTML2FormApplication }

  THTML2FormApplication = Class(TCustomApplication)
  Private
    FConv: THTMLToFormELements ;
    FGen : TWebCoreFormCodeGen;
    procedure ReadConfigFile(const aFileName: String);
    procedure Usage(S: String);
    procedure WriteLog(Sender: TObject; const Msg: String);
  Protected
    Procedure DoRun; override;
  Public
    Constructor Create(aOwner: TComponent); override;
    Destructor Destroy; override;
  end;


{ TMyApp }

procedure THTML2FormApplication.Usage(S : String);

begin
  if S<>'' then
    Writeln('Error : ',S);
  Writeln('Usage : ',ExtractFileName(ExeName),' -i file -o file [options]');
  Writeln('Where options is one or more of: ');
  Writeln('-h --help                    this message');
  Writeln('-b --below-id=ID             Only create elements for child elements of element ID');
  Writeln('-f --formclass=NAME          name of pascal form class');
  Writeln('-F --form-file               Generate a form file.');
  Writeln('-g --getelementfunction=NAME Name of getelement function');
  Writeln('-e --events                  emit code to bind events');
  Writeln('-i --input=file              html file to read');
  writeln('-m --map=file                read tag to pascal class map from file');
  writeln('-n --no-bind                 Do not call bindelements in constructor');
  writeln('-o --output=file             pascal file to write');
  Writeln('-p --parentclass=NAME        name of pascal form parent class');
  Writeln('-x --exclude=List            Comma-separated list of IDs to exclude. if starts with @, then load from file');
  Halt(Ord(S<>''));
end;

procedure THTML2FormApplication.WriteLog(Sender: TObject; const Msg: String);
begin
  Writeln(Msg);
end;

procedure THTML2FormApplication.ReadConfigFile(const aFileName : String);

Var
  D : TJSONData;
  J : TJSONObject absolute D;
  F : TFileStream;
  H : THTML2ClassOptions;

begin
  D:=Nil;
  H:=nil;
  F:=TFileStream.Create(aFileName,fmOpenRead or fmShareDenyWrite);
  try
    D:=GetJSON(F);
    if D is TJSONObject then
      begin
      H:=THTML2ClassOptions.Create;
      H.FromJSON(J);
      FConv.LoadOptions(H);
      FGen.LoadOptions(H);
      end;
  finally
    H.Free;
    F.Free;
    D.Free;
  end;
end;

procedure THTML2FormApplication.DoRun;

var
  S,IFN,OFN : String;
begin
  StopOnException:=True;
  Terminate;
  S:=CheckOptions('c:hi:o:f:ep:b:g:x:m:Fndqa',
                  ['config:','help','input:','output:','formclass:','event',
                   'parentclass:','below-id:','getelementfunction:','exclude:',
                   'map:','form-file','no-bind','defaultelements','quiet','actionlist']);
  if (S<>'') or HasOption('h','help') then
    Usage(S);
  IFN:=GetOptionValue('i','input');
  OFN:=GetOptionValue('o','output');
  FConv.DefaultElements:=HasOption('d','defaultelements');
  if HasOption('c','config') then
    ReadConfigFile(GetOptionValue('c','config'));
  if HasOption('f','formclass') then
    FGen.FormClassName:=GetOptionValue('f','formclass');
  if HasOption('p','parentclass') then
    FGen.ParentClassName:=GetOPtionValue('p','parentclass');
  if HasOption('g','getelementfunction') then
    FGen.GetElementFunction:=GetOptionValue('g','getelementfunction') ;
  if HasOption('F','form-file') or hasOption('a','actionlist') then
    begin
    FGen.Options:=FGen.Options+[foFormFile];
    FGen.EventSignature:='Sender : TObject';
    FGen.EventModifiers:='';
    FGen.AddMethods:=[];
    if hasOption('a','actionlist') then
      FGen.WebCoreOptions:=FGen.WebCoreOptions+[wcoUseActionList];
    end;
  if hasOption('e','event') then
    FGen.Options:=FGen.Options+[foEvents];
  if hasOption('n','no-bind') then
    FGen.Options:=FGen.Options-[foBindInConstructor];
  if HasOption('m','map') then
    begin
    FConv.Map.LoadFromFile(GetOptionValue('m','map'));
    FConv.DefaultElements:=HasOption('d','defaultelements');
    end;
  if Not HasOption('q','quiet') then
    FCOnv.OnLog:=@WriteLog;
  if HasOption('x','exclude') then
    begin
    S:=GetOPtionValue('x','exclude');
    if (S<>'') and (S[1]='@') then
      FConv.ExcludeIDS.LoadFromFile(Copy(S,2,Length(S)-1))
    else
      FConv.ExcludeIDS.CommaText:=S;
    end;
  if HasOption('b','below-id') then
    FConv.BelowID:=GetOptionValue('b','below-id');
  if IFN='' then
    Usage('Need input file');
  if OFN='' then
    Usage('Need output file');
  FConv.LoadFromFile(IFN);
  if FConv.FormElements.Count=0 then
    Writeln('No elements found')
  else
    begin
    FGen.FormElements:=FConv.FormElements;
    FGen.OutputUnitName:=ChangeFileExt(ExtractFIleName(ofn),'');
    FGen.Execute;
    FGen.SaveToFile(OFN);
    if foFormFile in FGen.Options then
      FGen.FormSource.SaveToFile(ChangeFileExt(OFN,'.dfm'));
    end;
end;

constructor THTML2FormApplication.Create(aOwner: TComponent);
begin
  inherited Create(aOwner);
  FConv:=THTMLToFormELements.Create(Self);
  FGen:=TWebCoreFormCodeGen.Create(Self);
end;

destructor THTML2FormApplication.Destroy;
begin
  FreeAndNil(FGen);
  FreeAndNil(FConv);
  inherited Destroy;
end;


begin
  With THTML2FormApplication.Create(Nil) do
    try
      Initialize;
      Run;
    finally
      Free;
    end;

end.

