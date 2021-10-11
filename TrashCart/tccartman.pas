 (**      TCCartman.Pas by Alexander Myasnikov                      **)
 (**      Fixed Cartman Tiny block cipher 1.1mk for TrashCart  PRNG **)
 (**      Cartman encrypts 128 bit block with 256..1024 bit key     **)
 (**      Gives much better transforming with new key schedule      **)
 (**      Freeware for any use,  non-patented, opensource cipher    **)
 (**      WEB:       www.darksoftware.narod.ru                      **)


unit tccartman;

{$Q-}
{$R-}


interface


const
  keysizebits  = 256;
  keysizebytes = keysizebits div 8;

type
  t128buf = array [0..3] of longword;

type
  p128buf = ^t128buf;


procedure tccartman_crypt (v: p128buf);
// Encrypt four 32 bit LongWords

procedure tccartman_decrypt (v: p128buf);
// Decrypt four 32 bit LongWords

procedure tccartman_setkey (k: pointer);
// Set's the key (Pointer to keysize*4 bytes block)


implementation

const

  keysize = keysizebytes div 4;

const

  subkeysize = keysize div 2; //  Size of subkey = full subkeysize for cartman function


var
  idx_box1: array [0..subkeysize - 1] of longword;

var
  idx_box2: array [0..subkeysize - 1] of longword;

var
  rot_box: array [0..keysize - 1] of longword;

var
  key: array [0..keysize - 1] of longword;

var
  subkey1: array [0..subkeysize - 1] of longword;

  subkey2: array [0..subkeysize - 1] of longword;

var
  idx1null: longword = 0;
  idx2null: longword = 0;
  idx3null: longword = 0;


function ror32 (N, R: longword): longword;
asm
  MOV EAX,N
  MOV ECX, R
  ROR EAX, CL
end;


function rol32 (N, R: longword): longword;
asm
  MOV EAX,N
  MOV ECX, R
  ROL EAX,CL
end;


procedure make_transform_box ();
var
  i: longword;
begin

  idx1null := 0;
  idx2null := 0;
  idx3null := 0;

  for i := 0 to subkeysize - 1 do
    begin
    idx_box1[i] := (ror32(key[i] + (key[i] shl 4) xor (key[i] shr 5),
      (i mod 31) + 1)) mod (subkeysize - 1);
    idx1null := (idx1null * (idx1null + 1) shr 1) + key[i];
    end;

  for i := subkeysize to keysize - 1 do
    begin
    idx_box2[(keysize - 1) - i] :=
      (rol32(key[i] + (key[i] shl 4) xor (key[i] shr 5), (i mod 31) + 1)) mod
      (subkeysize - 1);
    idx2null := (idx2null * (idx2null + 1) shr 1) + key[i];
    end;

  for i := 0 to (keysize - 1) do
    begin
    rot_box[i] := ((rol32(key[i] xor (i + 1), (((keysize - 1) - i) mod 31) + 1)) mod
      31) + 1;
    Inc(idx3null, key[i] * (i + 1));
    end;

  idx1null := (idx1null xor (idx1null shr 16)) mod subkeysize;
  idx2null := (idx2null xor (idx2null shr 16)) mod subkeysize;
  idx3null := (idx3null xor (idx3null shr 16)) mod subkeysize;

end;


procedure tccartman_crypt (v: p128buf);
var
  i, k1, k2, k3, k4, rot1, rot2, idx1, idx2, n, v0, v1: longword;

begin

  for n := 0 to subkeysize - 1 do
    begin

    idx1 := idx_box1[n];
    idx2 := idx_box2[n];

    for i := 0 to (subkeysize - 1) do
      begin

      k1 := subkey1[idx1];
      k2 := subkey1[idx1 + 1];
      k3 := subkey2[idx2];
      k4 := subkey2[idx2 + 1];

      rot1 := rot_box[idx1 + idx2];
      rot2 := rot_box[idx1 + idx2 + 1];

      if idx1 = idx1null then
        Inc(v[0], v[3] + ror32((v[1] + (v[1] shl 6) xor (v[1] shr 9)), rot1) + k1)
      else
        Inc(v[0], v[3] + ror32((v[1] + (v[1] shl 6) xor (v[1] shr 9)) + k1, rot1));

      if idx2 = idx2null then
        Inc(v[1], v[2] + ror32((v[0] + (v[0] shl 6) xor (v[0] shr 9)), rot2) + k2)
      else
        Inc(v[1], v[2] + ror32((v[0] + (v[0] shl 6) xor (v[0] shr 9)) + k2, rot2));


      if i = idx3null then
        begin
        Inc(v[2], ((v[0] + (v[0] shl 4) xor (v[0] shr 5)) + k3));
        Inc(v[3], ((v[1] + (v[1] shl 4) xor (v[1] shr 5)) + k4));
        end
      else
        begin
        v[2] := v[2] xor ((v[0] + (v[0] shl 4) xor (v[0] shr 5)) + k3);
        v[3] := v[3] xor ((v[1] + (v[1] shl 4) xor (v[1] shr 5)) + k4);
        end;


      v0 := v[0];
      v1 := v[1];
      v[0] := v[2];
      v[1] := v[3];
      v[2] := v0;
      v[3] := v1;

      if idx1 <> (subkeysize - 2) then
        Inc(idx1)
      else
        idx1 := 0;

      if idx2 <> (subkeysize - 2) then
        Inc(idx2)
      else
        idx2 := 0;

      end;

    end;

end;


procedure tccartman_decrypt (v: p128buf);
var
  i, k1, k2, k3, k4, rot1, rot2, idx1, idx2, n, v0, v1: longword;

begin

  for n := subkeysize - 1 downto 0 do
    begin

    idx1 := idx_box1[n];
    idx2 := idx_box2[n];

    for i := subkeysize - 1 downto 0 do
      begin

      k1 := subkey1[idx1];
      k2 := subkey1[idx1 + 1];
      k3 := subkey2[idx2];
      k4 := subkey2[idx2 + 1];

      rot1 := rot_box[idx1 + idx2];
      rot2 := rot_box[idx1 + idx2 + 1];

      v0 := v[0];
      v1 := v[1];
      v[0] := v[2];
      v[1] := v[3];
      v[2] := v0;
      v[3] := v1;

      if i = idx3null then
        begin
        Dec(v[3], ((v[1] + (v[1] shl 4) xor (v[1] shr 5)) + k4));
        Dec(v[2], ((v[0] + (v[0] shl 4) xor (v[0] shr 5)) + k3));

        end
      else
        begin
        v[3] := v[3] xor ((v[1] + (v[1] shl 4) xor (v[1] shr 5)) + k4);
        v[2] := v[2] xor ((v[0] + (v[0] shl 4) xor (v[0] shr 5)) + k3);
        end;


      if idx2 = idx2null then
        Dec(v[1], v[2] + ror32((v[0] + (v[0] shl 6) xor (v[0] shr 9)), rot2) + k2)
      else
        Dec(v[1], v[2] + ror32((v[0] + (v[0] shl 6) xor (v[0] shr 9)) + k2, rot2));

      if idx1 = idx1null then
        Dec(v[0], v[3] + ror32((v[1] + (v[1] shl 6) xor (v[1] shr 9)), rot1) + k1)
      else

        Dec(v[0], v[3] + ror32((v[1] + (v[1] shl 6) xor (v[1] shr 9)) + k1, rot1));

      if idx1 <> 0 then
        Dec(idx1)
      else
        idx1 := (subkeysize - 2);

      if idx2 <> 0 then
        Dec(idx2)
      else
        idx2 := (subkeysize - 2);

      end;

    end;

end;


procedure tccartman_setkey (k: pointer);
begin
  move(k^, key, (keysize * 4));

  make_transform_box();

  move(key, subkey1, subkeysize * 4);
  move(key[subkeysize], subkey2, subkeysize * 4);

end;


end.
