{
    This file is part of the Pas2JS tool chain
    Copyright (c) 2020 by Michael Van Canneyt

    This unit implements a HTML to DFM/LFM generator

    See the file COPYING.FPC, included in this distribution,
    for details about the copyright.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

 **********************************************************************}

unit webcoreformgen;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, formgen;

type
  TWebCoreFormFileCodeGen = Class;

  { TWebCoreFormCodeGen }
  TWebCoreOption = (wcoUseActionList);
  TWebCoreOptions = set of TWebCoreOption;


  TWebCoreFormCodeGen = Class(TFormCodeGen)
  private
    FListClassName: String;
    FListInstanceName: String;
    FWebCoreOptions: TWebCoreOptions;
    function GetWFF: TWebCoreFormFileCodeGen;
    procedure SetListClassName(AValue: String);
    procedure SetListInstanceName(AValue: String);
    procedure SetWebCoreOptions(AValue: TWebCoreOptions);
  Protected
    procedure EmitPublishedSection; override;
    function CreateFormFileGen : TFormFileCodeGen; override;
    Property WebFormFile : TWebCoreFormFileCodeGen Read GetWFF;
  Published
    Property WebCoreOptions : TWebCoreOptions Read FWebCoreOptions Write SetWebCoreOptions;
    Property ListClassName : String Read FListClassName Write SetListClassName;
    Property ListInstanceName : String Read FListInstanceName Write SetListInstanceName;
  end;

  { TWebCoreFormFileCodeGen }

  TWebCoreFormFileCodeGen = Class(TFormFileCodeGen)
  private
    FListClassName: String;
    FListInstanceName: String;
    FWebCoreOptions: TWebCoreOptions;
    procedure EmitItem(el: TFormElement; aEvent, aHandler: String);
    procedure GenerateListItems;
  Protected
    Procedure GenerateElements; override;
  Public
    Constructor create(aOwner : TComponent); override;
  Published
    Property WebCoreOptions : TWebCoreOptions Read FWebCoreOptions Write FWebCoreOptions;
    Property ListClassName : String Read FListClassName Write FListClassName;
    Property ListInstanceName : String Read FListInstanceName Write FListInstanceName;
  end;

implementation

{ TWebCoreFormFileCodeGen }

procedure TWebCoreFormFileCodeGen.EmitItem(el : TFormElement; aEvent,aHandler : String);


begin
  AddLn('item');
  Indent;
  AddLn('ID = ''%s''',[el.HTMLID]);
  if (aEvent<>'') then
    begin
    Addln('Event = %s',[aEvent]);
    if (aHandler<>'') then
      AddLn('OnExecute = %s',[aHandler]);
    end;
  AddLn('TargetAction = actNone');
  Undent;
  AddLn('end');
end;

procedure TWebCoreFormFileCodeGen.GenerateListItems;



Var
  I : Integer;
  El : TFormElement;
  S,EN,EH : String;

begin
  Addln('Actions = <');
  Indent;
  For I:=0 to FormElements.Count-1 do
    begin
    el:=FormElements[i];
    // Web Core does not support multiple events on 1 webaction,
    // So, we must generate 1 item per event.
    if DoEvents and (El.Events.Count>0) then
      begin
      For S in El.Events do
        begin
        TFormCodeGen.GetEventNameAndHandler(S,El.Name,EN,EH);
        EmitItem(El,EN,EH);
        end;
      end
    else
      EmitItem(El,'','');
    end;
  Undent;
  Addln('>');
end;

procedure TWebCoreFormFileCodeGen.GenerateElements;

begin
  if wcoUseActionList in WebcoreOptions then
    begin
    AddLn('object %s : %s',[ListInstanceName,ListClassName]);
    Indent;
    GenerateListItems;
    Undent;
    AddLn('end');
    end
  else
    inherited GenerateElements;
end;

constructor TWebCoreFormFileCodeGen.create(aOwner: TComponent);
begin
  inherited create(aOwner);
  ListInstanceName:='Elements';
  ListClassName:='TWebElementActionList';
end;

{ TWebCoreFormCodeGen }

procedure TWebCoreFormCodeGen.SetWebCoreOptions(AValue: TWebCoreOptions);
begin
  if FWebCoreOptions=AValue then Exit;
  FWebCoreOptions:=AValue;
  WebFormFile.WebCoreOptions:=aValue;
  if wcoUseActionList in aValue then
    begin
    EventSignature:='Sender: TObject; Element: TJSHTMLElementRecord; Event: TJSEventParameter';
    EventModifiers:='';
    end;
end;

function TWebCoreFormCodeGen.GetWFF: TWebCoreFormFileCodeGen;
begin
  Result:=Self.FormFileGenerator as TWebCoreFormFileCodeGen;
end;

procedure TWebCoreFormCodeGen.SetListClassName(AValue: String);
begin
  if FListClassName=AValue then Exit;
  FListClassName:=AValue;
  WebFormFile.ListClassName:=aValue;
end;

procedure TWebCoreFormCodeGen.SetListInstanceName(AValue: String);
begin
  if FListInstanceName=AValue then Exit;
  FListInstanceName:=AValue;
  WebFormFile.ListInstanceName:=aValue;
end;

procedure TWebCoreFormCodeGen.EmitPublishedSection;
begin
  if wcoUseActionList in WebcoreOptions then
    begin
    AddLn('%s : %s;',[ListInstanceName,ListClassName]);
    end
  else
    inherited EmitPublishedSection;
end;

function TWebCoreFormCodeGen.CreateFormFileGen: TFormFileCodeGen;
begin
  Result:=TWebCoreFormFileCodeGen.Create(Nil);
end;

end.

