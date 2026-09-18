package pdf

import (
	"strconv"
	"strings"
)

// The predefined simple-font encodings of the specification's Appendix D,
// as code to glyph name, and the glyph names this reader maps to Unicode.
// A glyph whose name is not here, and not of the uniXXXX or uXXXX form,
// is unmapped: rendered as U+FFFD and counted.

// asciiNames are the glyph names of codes 32 to 126 in StandardEncoding;
// WinAnsi and MacRoman differ at 39 and 96 only.
var asciiNames = strings.Fields(`space exclam quotedbl numbersign dollar percent ampersand quoteright
parenleft parenright asterisk plus comma hyphen period slash zero one two three four five six seven
eight nine colon semicolon less equal greater question at A B C D E F G H I J K L M N O P Q R S T U V
W X Y Z bracketleft backslash bracketright asciicircum underscore quoteleft a b c d e f g h i j k l m
n o p q r s t u v w x y z braceleft bar braceright asciitilde`)

func baseTable(quotesingle bool) [256]string {
	var t [256]string
	for i, n := range asciiNames {
		t[32+i] = n
	}
	if quotesingle {
		t[39] = "quotesingle"
		t[96] = "grave"
	}
	return t
}

func fill(t *[256]string, pairs string) {
	f := strings.Fields(pairs)
	for i := 0; i+1 < len(f); i += 2 {
		code, err := strconv.Atoi(f[i])
		if err != nil || code < 0 || code > 255 {
			continue
		}
		t[code] = f[i+1]
	}
}

var standardEncoding, winAnsiEncoding, macRomanEncoding, pdfDocEncodingUnused [256]string

func init() {
	standardEncoding = baseTable(false)
	fill(&standardEncoding, `161 exclamdown 162 cent 163 sterling 164 fraction 165 yen 166 florin 167 section
168 currency 169 quotesingle 170 quotedblleft 171 guillemotleft 172 guilsinglleft 173 guilsinglright 174 fi 175 fl
177 endash 178 dagger 179 daggerdbl 180 periodcentered 182 paragraph 183 bullet 184 quotesinglbase 185 quotedblbase
186 quotedblright 187 guillemotright 188 ellipsis 189 perthousand 191 questiondown 193 grave 194 acute 195 circumflex
196 tilde 197 macron 198 breve 199 dotaccent 200 dieresis 202 ring 203 cedilla 205 hungarumlaut 206 ogonek 207 caron
208 emdash 225 AE 227 ordfeminine 232 Lslash 233 Oslash 234 OE 235 ordmasculine 241 ae 245 dotlessi 248 lslash
249 oslash 250 oe 251 germandbls`)

	winAnsiEncoding = baseTable(true)
	fill(&winAnsiEncoding, `127 bullet 128 Euro 129 bullet 130 quotesinglbase 131 florin 132 quotedblbase 133 ellipsis 134 dagger
135 daggerdbl 136 circumflex 137 perthousand 138 Scaron 139 guilsinglleft 140 OE 141 bullet 142 Zcaron 143 bullet 144 bullet
145 quoteleft 146 quoteright 147 quotedblleft 148 quotedblright 149 bullet 150 endash 151 emdash 152 tilde 153 trademark
154 scaron 155 guilsinglright 156 oe 157 bullet 158 zcaron 159 Ydieresis 160 space 161 exclamdown 162 cent 163 sterling
164 currency 165 yen 166 brokenbar 167 section 168 dieresis 169 copyright 170 ordfeminine 171 guillemotleft 172 logicalnot
173 hyphen 174 registered 175 macron 176 degree 177 plusminus 178 twosuperior 179 threesuperior 180 acute 181 mu
182 paragraph 183 periodcentered 184 cedilla 185 onesuperior 186 ordmasculine 187 guillemotright 188 onequarter
189 onehalf 190 threequarters 191 questiondown 192 Agrave 193 Aacute 194 Acircumflex 195 Atilde 196 Adieresis 197 Aring
198 AE 199 Ccedilla 200 Egrave 201 Eacute 202 Ecircumflex 203 Edieresis 204 Igrave 205 Iacute 206 Icircumflex
207 Idieresis 208 Eth 209 Ntilde 210 Ograve 211 Oacute 212 Ocircumflex 213 Otilde 214 Odieresis 215 multiply 216 Oslash
217 Ugrave 218 Uacute 219 Ucircumflex 220 Udieresis 221 Yacute 222 Thorn 223 germandbls 224 agrave 225 aacute
226 acircumflex 227 atilde 228 adieresis 229 aring 230 ae 231 ccedilla 232 egrave 233 eacute 234 ecircumflex
235 edieresis 236 igrave 237 iacute 238 icircumflex 239 idieresis 240 eth 241 ntilde 242 ograve 243 oacute
244 ocircumflex 245 otilde 246 odieresis 247 divide 248 oslash 249 ugrave 250 uacute 251 ucircumflex 252 udieresis
253 yacute 254 thorn 255 ydieresis`)

	macRomanEncoding = baseTable(true)
	fill(&macRomanEncoding, `128 Adieresis 129 Aring 130 Ccedilla 131 Eacute 132 Ntilde 133 Odieresis 134 Udieresis 135 aacute
136 agrave 137 acircumflex 138 adieresis 139 atilde 140 aring 141 ccedilla 142 eacute 143 egrave 144 ecircumflex
145 edieresis 146 iacute 147 igrave 148 icircumflex 149 idieresis 150 ntilde 151 oacute 152 ograve 153 ocircumflex
154 odieresis 155 otilde 156 uacute 157 ugrave 158 ucircumflex 159 udieresis 160 dagger 161 degree 162 cent
163 sterling 164 section 165 bullet 166 paragraph 167 germandbls 168 registered 169 copyright 170 trademark 171 acute
172 dieresis 173 notequal 174 AE 175 Oslash 176 infinity 177 plusminus 178 lessequal 179 greaterequal 180 yen 181 mu
182 partialdiff 183 summation 184 product 185 pi 186 integral 187 ordfeminine 188 ordmasculine 189 Omega 190 ae
191 oslash 192 questiondown 193 exclamdown 194 logicalnot 195 radical 196 florin 197 approxequal 198 Delta
199 guillemotleft 200 guillemotright 201 ellipsis 202 space 203 Agrave 204 Atilde 205 Otilde 206 OE 207 oe 208 endash
209 emdash 210 quotedblleft 211 quotedblright 212 quoteleft 213 quoteright 214 divide 215 lozenge 216 ydieresis
217 Ydieresis 218 fraction 219 currency 220 guilsinglleft 221 guilsinglright 222 fi 223 fl 224 daggerdbl
225 periodcentered 226 quotesinglbase 227 quotedblbase 228 perthousand 229 Acircumflex 230 Ecircumflex 231 Aacute
232 Edieresis 233 Egrave 234 Iacute 235 Icircumflex 236 Idieresis 237 Igrave 238 Oacute 239 Ocircumflex 240 apple
241 Ograve 242 Uacute 243 Ucircumflex 244 Ugrave 245 dotlessi 246 circumflex 247 tilde 248 macron 249 breve
250 dotaccent 251 ring 252 cedilla 253 hungarumlaut 254 ogonek 255 caron`)
}

// glyphNames is the subset of the Adobe Glyph List this reader carries:
// every name the three encodings above use, the Latin-1 and Latin
// Extended-A letters, the common punctuation and symbols, and the
// f-ligatures. Values are code points.
var glyphNames = map[string]rune{}

func init() {
	// name codepoint, hex.
	list := `space 20 exclam 21 quotedbl 22 numbersign 23 dollar 24 percent 25 ampersand 26 quotesingle 27
parenleft 28 parenright 29 asterisk 2A plus 2B comma 2C hyphen 2D period 2E slash 2F zero 30 one 31 two 32
three 33 four 34 five 35 six 36 seven 37 eight 38 nine 39 colon 3A semicolon 3B less 3C equal 3D greater 3E
question 3F at 40 bracketleft 5B backslash 5C bracketright 5D asciicircum 5E underscore 5F grave 60
braceleft 7B bar 7C braceright 7D asciitilde 7E nbspace A0 nonbreakingspace A0 exclamdown A1 cent A2 sterling A3
currency A4 yen A5 brokenbar A6 section A7 dieresis A8 copyright A9 ordfeminine AA guillemotleft AB
logicalnot AC sfthyphen AD softhyphen AD registered AE macron AF overscore AF degree B0 plusminus B1 twosuperior B2
threesuperior B3 acute B4 mu B5 mu1 B5 paragraph B6 periodcentered B7 middot B7 cedilla B8 onesuperior B9
ordmasculine BA guillemotright BB onequarter BC onehalf BD threequarters BE questiondown BF Agrave C0 Aacute C1
Acircumflex C2 Atilde C3 Adieresis C4 Aring C5 AE C6 Ccedilla C7 Egrave C8 Eacute C9 Ecircumflex CA Edieresis CB
Igrave CC Iacute CD Icircumflex CE Idieresis CF Eth D0 Ntilde D1 Ograve D2 Oacute D3 Ocircumflex D4 Otilde D5
Odieresis D6 multiply D7 Oslash D8 Ugrave D9 Uacute DA Ucircumflex DB Udieresis DC Yacute DD Thorn DE
germandbls DF agrave E0 aacute E1 acircumflex E2 atilde E3 adieresis E4 aring E5 ae E6 ccedilla E7 egrave E8
eacute E9 ecircumflex EA edieresis EB igrave EC iacute ED icircumflex EE idieresis EF eth F0 ntilde F1 ograve F2
oacute F3 ocircumflex F4 otilde F5 odieresis F6 divide F7 oslash F8 ugrave F9 uacute FA ucircumflex FB
udieresis FC yacute FD thorn FE ydieresis FF
Amacron 100 amacron 101 Abreve 102 abreve 103 Aogonek 104 aogonek 105 Cacute 106 cacute 107 Ccircumflex 108
ccircumflex 109 Cdotaccent 10A cdotaccent 10B Ccaron 10C ccaron 10D Dcaron 10E dcaron 10F Dcroat 110 dcroat 111
Emacron 112 emacron 113 Ebreve 114 ebreve 115 Edotaccent 116 edotaccent 117 Eogonek 118 eogonek 119 Ecaron 11A
ecaron 11B Gcircumflex 11C gcircumflex 11D Gbreve 11E gbreve 11F Gdotaccent 120 gdotaccent 121 Gcommaaccent 122
gcommaaccent 123 Hcircumflex 124 hcircumflex 125 Hbar 126 hbar 127 Itilde 128 itilde 129 Imacron 12A imacron 12B
Ibreve 12C ibreve 12D Iogonek 12E iogonek 12F Idotaccent 130 dotlessi 131 IJ 132 ij 133 Jcircumflex 134
jcircumflex 135 Kcommaaccent 136 kcommaaccent 137 kgreenlandic 138 Lacute 139 lacute 13A Lcommaaccent 13B
lcommaaccent 13C Lcaron 13D lcaron 13E Ldot 13F ldot 140 Lslash 141 lslash 142 Nacute 143 nacute 144
Ncommaaccent 145 ncommaaccent 146 Ncaron 147 ncaron 148 napostrophe 149 Eng 14A eng 14B Omacron 14C omacron 14D
Obreve 14E obreve 14F Ohungarumlaut 150 ohungarumlaut 151 OE 152 oe 153 Racute 154 racute 155 Rcommaaccent 156
rcommaaccent 157 Rcaron 158 rcaron 159 Sacute 15A sacute 15B Scircumflex 15C scircumflex 15D Scedilla 15E
scedilla 15F Scaron 160 scaron 161 Tcommaaccent 162 tcommaaccent 163 Tcaron 164 tcaron 165 Tbar 166 tbar 167
Utilde 168 utilde 169 Umacron 16A umacron 16B Ubreve 16C ubreve 16D Uring 16E uring 16F Uhungarumlaut 170
uhungarumlaut 171 Uogonek 172 uogonek 173 Wcircumflex 174 wcircumflex 175 Ycircumflex 176 ycircumflex 177
Ydieresis 178 Zacute 179 zacute 17A Zdotaccent 17B zdotaccent 17C Zcaron 17D zcaron 17E longs 17F florin 192
Scommaaccent 218 scommaaccent 219 circumflex 2C6 caron 2C7 macron 2C9 breve 2D8 dotaccent 2D9 ring 2DA ogonek 2DB
tilde 2DC hungarumlaut 2DD
Alpha 391 Beta 392 Gamma 393 Delta 2206 Epsilon 395 Zeta 396 Eta 397 Theta 398 Iota 399 Kappa 39A Lambda 39B Mu 39C
Nu 39D Xi 39E Omicron 39F Pi 3A0 Rho 3A1 Sigma 3A3 Tau 3A4 Upsilon 3A5 Phi 3A6 Chi 3A7 Psi 3A8 Omega 2126
alpha 3B1 beta 3B2 gamma 3B3 delta 3B4 epsilon 3B5 zeta 3B6 eta 3B7 theta 3B8 iota 3B9 kappa 3BA lambda 3BB
mu 3BC nu 3BD xi 3BE omicron 3BF pi 3C0 rho 3C1 sigma1 3C2 sigma 3C3 tau 3C4 upsilon 3C5 phi 3C6 chi 3C7 psi 3C8
omega 3C9 theta1 3D1 phi1 3D5 omega1 3D6
endash 2013 emdash 2014 quoteleft 2018 quoteright 2019 quotesinglbase 201A quotereversed 201B quotedblleft 201C
quotedblright 201D quotedblbase 201E dagger 2020 daggerdbl 2021 bullet 2022 ellipsis 2026 perthousand 2030
minute 2032 second 2033 guilsinglleft 2039 guilsinglright 203A fraction 2044 Euro 20AC trademark 2122
arrowleft 2190 arrowup 2191 arrowright 2192 arrowdown 2193 arrowboth 2194 partialdiff 2202 increment 2206
product 220F summation 2211 minus 2212 radical 221A infinity 221E integral 222B approxequal 2248 notequal 2260
equivalence 2261 lessequal 2264 greaterequal 2265 lozenge 25CA circlemultiply 2297 circleplus 2295
checkmark 2713 apple F8FF ff FB00 fi FB01 fl FB02 ffi FB03 ffl FB04 dotlessj 237 Ldotaccent 13F ldotaccent 140
onethird 2153 twothirds 2154 oneeighth 215B threeeighths 215C fiveeighths 215D seveneighths 215E
franc 20A3 lira 20A4 peseta 20A7 dong 20AB colonmonetary 20A1 cruzeiro 20A2 ordfeminine AA
copyrightserif A9 registerserif AE trademarkserif 2122 copyrightsans A9 registersans AE trademarksans 2122
angleleft 2329 angleright 232A openbullet 25E6 filledbox 25A0 H22073 25A1 H18543 25AA H18551 25AB
triagup 25B2 triagrt 25BA triagdn 25BC triaglf 25C4 circle 25CB H18533 25CF invbullet 25D8 invcircle 25D9
smileface 263A invsmileface 263B sun 263C female 2640 male 2642 spade 2660 club 2663 heart 2665 diamond 2666
musicalnote 266A musicalnotedbl 266B universal 2200 existential 2203 emptyset 2205 gradient 2207 element 2208
notelement 2209 suchthat 220B asteriskmath 2217 proportional 221D angle 2220 logicaland 2227 logicalor 2228
intersection 2229 union 222A therefore 2234 similar 223C congruent 2245 propersubset 2282 propersuperset 2283
notsubset 2284 reflexsubset 2286 reflexsuperset 2287 perpendicular 22A5 dotmath 22C5 carriagereturn 21B5
arrowdblleft 21D0 arrowdblup 21D1 arrowdblright 21D2 arrowdbldown 21D3 arrowdblboth 21D4 weierstrass 2118
Ifraktur 2111 Rfraktur 211C aleph 2135 registered AE degree B0`
	f := strings.Fields(list)
	for i := 0; i+1 < len(f); i += 2 {
		v, err := strconv.ParseUint(f[i+1], 16, 32)
		if err != nil {
			continue
		}
		glyphNames[f[i]] = rune(v)
	}
	for i, n := range asciiNames {
		glyphNames[n] = rune(32 + i)
	}
	for c := 'A'; c <= 'Z'; c++ {
		glyphNames[string(c)] = c
		glyphNames[string(c+32)] = c + 32
	}
}

// glyphToRune maps a glyph name to a code point: the list above, the
// uniXXXX and uXXXX[XX] forms, and a name with a suffix after a period
// (".sc", ".alt") by its stem. ok is false for a name it cannot map.
func glyphToRune(name string) (rune, bool) {
	if r, ok := glyphNames[name]; ok {
		return r, true
	}
	if i := strings.IndexByte(name, '.'); i > 0 {
		return glyphToRune(name[:i])
	}
	if strings.HasPrefix(name, "uni") && len(name) >= 7 {
		if v, err := strconv.ParseUint(name[3:7], 16, 32); err == nil && validScalar(rune(v)) {
			return rune(v), true
		}
	}
	if strings.HasPrefix(name, "u") && len(name) >= 5 && len(name) <= 7 {
		if v, err := strconv.ParseUint(name[1:], 16, 32); err == nil && validScalar(rune(v)) {
			return rune(v), true
		}
	}
	return 0, false
}

// validScalar reports whether r is a Unicode scalar value: what may be
// written into text. A control character is one, and is admitted here on
// purpose -- the record's normalisation is what removes it, after the first
// character of the text has been looked at, so the order that normalisation
// fixes is kept.
func validScalar(r rune) bool {
	if r < 0 || r > 0x10FFFF || (r >= 0xD800 && r <= 0xDFFF) {
		return false
	}
	return true
}
