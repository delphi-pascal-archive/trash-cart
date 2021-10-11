 (**      TrashCart.Pas by Alexander Myasnikov                      **)
 (**      TrashCart PRNG  based on Cartman block cipher             **)
 (**      Freeware for any use,  non-patented, opensource cipher    **)
 (**      WEB:       www.darksoftware.narod.ru                      **)
 (**      Cartman block cipher project information                  **)
 (**      WEB:       www.alexanderwdark.narod.ru                    **)


unit trashcart;

interface


type
  TTrashCartPRNG = object

  public
    // Recommended init routine (key points to key = keysize bytes + IV  = 16 bytes)
    // Check keysize constant in Cartman cipher unit
    procedure tc_init (key: pointer);

    // Init by longint seed by key expand routine using also some times
    procedure tc_seed (seed: longint);

    // Init by longint seed by key expand routine
    procedure tc_lgseed (seed: longint);


    // Generate len bytes and move to data buffer
    procedure tc_read (Data: pointer; len: integer);

    function tc_word: word;
    function tc_uint64: uint64;
    function tc_int64: int64;
    function tc_longword: longword;
    function tc_longint: longint;
    function tc_byte: byte;
  private
    keystream: array [0..15] of byte;
    procedure tc_next ();
    function RDTSC: int64; register;
  end;

var
  TrashPRNG: TTrashCartPRNG;

implementation


uses tccartman, Windows;

type
  TLongIntKey = array [0.. ((16 + keysizebytes) div 4)-1] of longint;

type
  PLongIntKey = ^TLongIntKey;


function TTrashCartPRNG.RDTSC: int64; register;
asm
  RDTSC
end;

procedure TTrashCartPRNG.tc_init (key: pointer);
begin
  tccartman_setkey(key);
  longword(key) := longword(key) + keysizebytes;
  move(key^, keystream, 16);
end;

procedure TTrashCartPRNG.tc_seed (seed: longint);
var
  key: pointer;
  i: integer;
begin
  GetMem(key, 16 + keysizebytes);

  PLongIntKey(key)[0] := seed;
  PLongIntKey(key)[1] := longint(GetTickCount());
  longword(key) := longword(key) + 8;
  PInt64(key)^  := RDTSC;
  longword(key) := longword(key) + 8;
  PLongIntKey(key)[0] := seed * 69069 + 1;
  for i := 1 to ((16 + keysizebytes) div 4) - 5 do
    PLongIntKey(key)[i] := PLongIntKey(key)[i - 1] * 69069 + 1;
  longword(key) := longword(key) - 16;
  tc_init(key);
  FreeMem(key);
end;


procedure TTrashCartPRNG.tc_lgseed (seed: longint);
var
  key: pointer;
  i: integer;
begin
  GetMem(key, 16 + keysizebytes);
  PLongIntKey(key)[0] := seed;

  for i := 1 to ((16 + keysizebytes) div 4) - 1 do
    PLongIntKey(key)[i] := PLongIntKey(key)[i - 1] * 69069 + 1;
  tc_init(key);
  FreeMem(key);
end;


procedure TTrashCartPRNG.tc_next ();
begin
  tccartman_crypt(@keystream);
end;


procedure TTrashCartPRNG.tc_read (Data: pointer; len: integer);
var
  buflen, i: integer;
begin

  repeat

    if len >= 16 then
      buflen := 16
    else
      buflen := len;

    fillchar(Data^, buflen, 0);

    tc_next();

    for I := 0 to buflen - 1 do
      begin
      byte(Data^) := keystream[i];
      longword(Data) := longword(Data) + 1;
      end;


    Dec(len, buflen);

  until len <= 0;

end;


function TTrashCartPRNG.tc_byte: byte;
begin
  tc_read(@Result, 1);
end;

function TTrashCartPRNG.tc_longint: longint;
begin
  tc_read(@Result, 4);
end;

function TTrashCartPRNG.tc_longword: longword;
begin
  tc_read(@Result, 4);
end;

function TTrashCartPRNG.tc_int64: int64;
begin
  tc_read(@Result, 8);
end;

function TTrashCartPRNG.tc_uint64: uint64;
begin
  tc_read(@Result, 8);
end;

function TTrashCartPRNG.tc_word: word;
begin
  tc_read(@Result, 2);
end;


end.
