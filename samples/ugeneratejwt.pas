unit uGenerateJWT;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Graphics, Dialogs, StdCtrls, LazJWT, DateUtils;

type

  { TfrLazJWT }

  TfrLazJWT = class(TForm)
    btGenerateToken: TButton;
    btCustomPayLoad: TButton;
    btValidateSignature: TButton;
    btValidateToken: TButton;
    edSecretKey: TEdit;
    edToken: TEdit;
    Label1: TLabel;
    mDecoded: TMemo;
    procedure btCustomPayLoadClick(Sender: TObject);
    procedure btGenerateTokenClick(Sender: TObject);
    procedure btValidateSignatureClick(Sender: TObject);
    procedure btValidateTokenClick(Sender: TObject);
  private
    FUseCustomPayLoad: Boolean;
  public

  end;

var
  frLazJWT: TfrLazJWT;

implementation

uses
  StrUtils, fpjson;

{$R *.lfm}

{ TfrLazJWT }

procedure TfrLazJWT.btGenerateTokenClick(Sender: TObject);
var
  LObject: TJSONObject;
begin
  LObject:=TJSONObject(GetJSON('{"teste": 12345}'));
  FUseCustomPayLoad := False;
  edToken.Text := TLazJWT
                    .New
                    .SecretJWT(edSecretKey.Text)
                    .Iss('1234567890')
                    .Sub('1234567890')
                    .Aud('djsystem')
                    {.Exp(1516239022)
                    .Nbf(1516239022)
                    .Iat(1516239022)
                    .JTI('123456') }
                    .CustomClaims(LObject)
                    .AddClaim('Teste', 'String')
                    .AddClaim('Boolean', True)
                    .AddClaim('Inteiro', 1)
                    .AddClaim('Jsonnn',GetJSON('{"Fld1" : "Hello", "Fld2" : 42, "Colors" : ["Red", "Green", "Blue"]}'))
                    .Token;
  //LObject.Free;
end;

procedure TfrLazJWT.btCustomPayLoadClick(Sender: TObject);
var
  LCustomPayLoad: TJSONData;
begin
  FUseCustomPayLoad := True;
  LCustomPayLoad := GetJSON('{"Fld1" : "Hello", "Fld2" : 42, "Colors" : ["Red", "Green", "Blue"]}');
  edToken.Text := TLazJWT
                    .New
                    .SecretJWT(edSecretKey.Text)
                    .CustomPayLoad(LCustomPayLoad)
                    .Token;
end;

procedure TfrLazJWT.btValidateSignatureClick(Sender: TObject);
var
  LLazJWT: ILazJWT;
begin
  LLazJWT := TLazJWT.Create;
  LLazJWT
    .UseCustomPayLoad(FUseCustomPayLoad)
    .Token(edToken.Text)
    .SecretJWT(edSecretKey.Text);
  mDecoded.Lines.Clear;
  mDecoded.Lines.Add('HEADER');
  mDecoded.Lines.Add('');
  mDecoded.Lines.Add(LLazJWT.Header);
  mDecoded.Lines.Add('');
  mDecoded.Lines.Add('PAYLOAD');
  mDecoded.Lines.Add('');
  mDecoded.Lines.Add(LLazJWT.PayLoad);
  mDecoded.Lines.Add('');
  mDecoded.Lines.Add('AsString');
  mDecoded.Lines.Add('');
  mDecoded.Lines.Add(LLazJWT.AsString);
  mDecoded.Lines.Add('');
  mDecoded.Lines.Add('Signature '+IfThen(LLazJWT.ValidateSignature,'Verified','Invalid'));
end;

procedure TfrLazJWT.btValidateTokenClick(Sender: TObject);
begin
  mDecoded.Lines.Clear;
  try
    TLazJWT
      .New(TLazJWTConfig
             .New
             .IsRequiredSubject(False)
             .IsRequiredIssuedAt(False)
             .IsRequiredNotBefore(False)
             .IsRequiredExpirationTime(False)
             .IsRequireAudience(True)
             .ExpectedAudience(['lazarus','djsystem'])
             )
      .UseCustomPayLoad(FUseCustomPayLoad)
      .Token(edToken.Text)
      .SecretJWT(edSecretKey.Text)
      .ValidateToken;
    mDecoded.Lines.Add('Token Verified');
  except
    On E: Exception do
    begin
      mDecoded.Lines.Add(E.Message);
    end;
  end;
end;

end.

