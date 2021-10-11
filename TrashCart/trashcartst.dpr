program trashcartst;

{$APPTYPE CONSOLE}

uses
  SysUtils,
  Windows,
  tccartman in 'tccartman.pas',
  trashcart in 'trashcart.pas';

var
  F: file;
var
  i{, n}: integer;
var
  buf: array [0..255] of byte;

{
  var  key: array [0..16 + keysizebytes] of byte; }

begin

{
  for I := 0 to (16 + keysizebytes) - 1 do
    begin
    key[i] := i;
    end;

    }

  //TrashPRNG.tc_init(@key);
  //TrashPRNG.tc_seed(76);
  TrashPRNG.tc_lgseed(GetTickCount);

  Assign(f, ParamStr(0) + '.random');
  rewrite(f, 1);
  for I := 0 to 16383 do
    begin

    //    for n := 0 to 255 do
    //      buf[n] := TrashPRNG.tc_byte();

    TrashPRNG.tc_read(@buf, 256);

    blockwrite(f, buf, 256);

    end;

  closefile(f);

end.
