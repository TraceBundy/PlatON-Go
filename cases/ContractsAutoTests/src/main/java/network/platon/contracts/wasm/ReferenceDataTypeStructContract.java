package network.platon.contracts.wasm;

import com.alaya.abi.wasm.WasmFunctionEncoder;
import com.alaya.abi.wasm.datatypes.WasmFunction;
import com.alaya.crypto.Credentials;
import com.alaya.protocol.Web3j;
import com.alaya.protocol.core.RemoteCall;
import com.alaya.protocol.core.methods.response.TransactionReceipt;
import com.alaya.rlp.wasm.datatypes.Uint64;
import com.alaya.tx.TransactionManager;
import com.alaya.tx.WasmContract;
import com.alaya.tx.gas.GasProvider;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * <p>Auto generated code.
 * <p><strong>Do not modify!</strong>
 * <p>Please use the <a href="https://github.com/PlatONnetwork/client-sdk-java/releases">platon-web3j command line tools</a>,
 * or the com.alaya.codegen.WasmFunctionWrapperGenerator in the 
 * <a href="https://github.com/PlatONnetwork/client-sdk-java/tree/master/codegen">codegen module</a> to update.
 *
 * <p>Generated with platon-web3j version 0.13.2.0.
 */
public class ReferenceDataTypeStructContract extends WasmContract {
    private static String BINARY_0 = "0x0061736d0100000001530f60027f7f0060017f017f60017f0060037f7f7f017f60037f7f7f0060027f7f017f60000060047f7f7f7f017f60047f7f7f7f0060027f7e0060017f017e60037e7e7f006000017f60017e017f60027e7e017f02a9020d03656e760c706c61746f6e5f70616e6963000603656e760d726c705f6c6973745f73697a65000103656e760f706c61746f6e5f726c705f6c697374000403656e760e726c705f62797465735f73697a65000503656e7610706c61746f6e5f726c705f6279746573000403656e760d726c705f753132385f73697a65000e03656e760f706c61746f6e5f726c705f75313238000b03656e7617706c61746f6e5f6765745f696e7075745f6c656e677468000c03656e7610706c61746f6e5f6765745f696e707574000203656e7617706c61746f6e5f6765745f73746174655f6c656e677468000503656e7610706c61746f6e5f6765745f7374617465000703656e7610706c61746f6e5f7365745f7374617465000803656e760d706c61746f6e5f72657475726e000003424106020403000203050002060103040a0a000101000102020101000506070200000501010900000d01000005090203000002010300000100030702030406040101080405017001030305030100020608017f0141e088040b073904066d656d6f72790200115f5f7761736d5f63616c6c5f63746f7273000d0f5f5f66756e63735f6f6e5f65786974002806696e766f6b6500170908010041010b020e120acb5741040010490b0300010b2601017f230041206b22032400200041206a200341086a2001200210101011200341206a24000b15002000200110141a2000200229030037031020000b1200200020011015200020012903103703100bbb0101047f230041206b22032400200041d0006a21040240034020014180086a2202410371044020014106460d02200141016a21010c010b0b200141fc076a21020340200241046a22022802002201417f73200141fffdfb776a7141808182847871450d000b0340200141ff0171450d01200241016a2d00002101200241016a21020c000b000b200441800820024180086b10132102200041f0006a22014214370300200041206a200341086a2002200110101011200341206a24000bda0101027f410a210320002d0000410171220404402000280200417e71417f6a21030b200320024f0440027f2004044020002802080c010b200041016a0b21032002044020032001200210480b200220036a41003a000020002d000041017104402000200236020420000f0b200020024101743a000020000f0b416f2104200341e6ffffff074d0440410b200341017422032002200320024b1b220341106a4170712003410b491b21040b2004102f220320012002104a200020023602042000200441017236020020002003360208200220036a41003a000020000ba10101037f20004200370200200041086a2202410036020020012d0000410171450440200020012902003702002002200141086a28020036020020000f0b20012802082103024020012802042201410a4d0440200020014101743a0000200041016a21020c010b200141106a4170712204102f21022000200136020420002004410172360200200020023602080b200220032001104a200120026a41003a000020000b5b00024020002d0000410171450440200041003b01000c010b200028020841003a00002000410036020420002d0000410171450d00200041003602000b20002001290200370200200041086a200141086a280200360200200110160b2201017f03402001410c470440200020016a4100360200200141046a21010c010b0b0bf60202047f017e230041d0016b22002400104910072201101822021008200041206a200041086a20022001101922014100101a02400240200041206a101b2204500d00418708101c200451044020014101101d0c020b418c08101c2004510440200041b8016a101e2102200042003703c8012001101f410347044010000b200041206a20014101101a200041206a20021020200041206a20014102101a2000200041206a101b3703c801200041206a10212101200041a8016a200210142102200020002903c801370398012001200220004198016a100f200110220c020b419d08101c200451044020014102101d0c020b41ae08101c2004520d002001102320004198016a200041206a1021220241206a10142101200041b8016a102422032001102510262003200041a8016a200110141027220128020c200141106a28020047044010000b20012802002001280204100c200128020c22030440200120033602100b200210220c010b10000b1028200041d0016a24000b9b0101047f230041106b220124002001200036020c2000047f41d008200041086a2202411076220041d0082802006a220336020041cc0841cc08280200220420026a41076a417871220236020002400240200341107420024d044041d008200341016a360200200041016a21000c010b2000450d010b200040000d0010000b20042001410c6a4104103a41086a0541000b2100200141106a240020000b0c00200020012002411c10290bc90202067f017e230041106b220324002001280208220520024b0440200341086a2001102c20012003280208200328020c102d36020c20032001102c410021052001027f410020032802002207450d001a410020032802042208200128020c2206490d001a200820062006417f461b210420070b360210200141146a2004360200200141003602080b200141106a210603402001280214210402402005200249044020040d01410021040b200020062802002004411410291a200341106a24000f0b20032001102c41002104027f410020032802002205450d001a410020032802042208200128020c2207490d001a200820076b2104200520076a0b2105200120043602142001200536021020032006410020052004102d104d2001200329030022093702102001200128020c2009422088a76a36020c2001200128020841016a22053602080c000b000b870202047f017e230041106b220324002000102a024002402000280204450d002000102a0240200028020022022c0000220141004e044020010d010c020b200141807f460d00200141ff0171220441b7014d0440200028020441014d04401000200028020021020b20022d00010d010c020b200441bf014b0d012000280204200141ff017141ca7e6a22014d04401000200028020021020b200120026a2d0000450d010b2000280204450d0020022d000041c001490d010b10000b200341086a2000102b200328020c220041094f044010000b200328020821010340200004402000417f6a210020013100002005420886842105200141016a21010c010b0b200341106a240020050b3901027e42a5c688a1c89ca7f94b210103402000300000220250450440200041016a2100200142b383808080207e20028521010c010b0b20010b3101017f23004180016b2202240020001023200241086a10212100200241086a20011102002000102220024180016a24000b190020004200370200200041086a41003602002000101620000b800101047f230041106b2201240002402000280204450d0020002802002d000041c001490d00200141086a2000102c200128020c210003402000450d01200141002001280208220320032000102d22046a20034520002004497222031b3602084100200020046b20031b2100200241016a21020c000b000b200141106a240020020ba10201057f230041206b22022400024002402000280204044020002802002d000041c001490d010b200241086a101e1a0c010b200241186a2000102b2000102e21030240024002400240200228021822000440200228021c220520034f0d010b41002100200241106a410036020020024200370308410021050c010b200241106a4100360200200242003703082000200520032003417f461b22046a21052004410a4b0d010b200220044101743a0008200241086a41017221030c010b200441106a4170712206102f21032002200436020c20022006410172360208200220033602100b03402000200546450440200320002d00003a0000200341016a2103200041016a21000c010b0b200341003a00000b2001200241086a1015200241206a24000bf50501087f230041e0006b220224002000101e210820004296ccebcaf2998af307370318200041206a2207101e1a200241306a1024220320002903181030200328020c200341106a28020047044010000b02402003280200220120032802042205100922064504400c010b2002410036022820024200370320200241206a2006103120012005200228022022012002280224220520016b100a417f470440200241c8006a200241086a200141016a20052001417f736a101922044100101a200241c8006a20071020200241c8006a20044101101a200041306a200241c8006a101b370300200621040b2001450d00200220013602240b200328020c22010440200320013602100b2004450440200720081032200041306a20002903103703000b200041386a101e2108200041c8006a220142f4b6fbddebefc6a0be7f370300200041d0006a101e2107200241c8006a1024220320012903001030200328020c200341106a28020047044010000b0240200328020022012003280204220510092206450440410021040c010b410021042002410036021020024200370308200241086a200610312001200520022802082201200228020c220520016b100a417f470440200241306a200141016a20052001417f736a101920071020200621040b2001450d002002200136020c0b200328020c22010440200320013602100b20044504402007200810320b20004200370360200041e8006a220142c2ecbedd86e3b3ee58370300200241c8006a1024220320012903001030200328020c200341106a28020047044010000b0240200328020022072003280204220110092206450440410021040c010b410021042002410036021020024200370308200241086a200610312007200120022802082201200228020c220520016b100a417f4704402000200241306a200141016a20052001417f736a1019101b370370200621040b2001450d002002200136020c0b200328020c22010440200320013602100b2004450440200020002903603703700b200241e0006a240020000bb009010d7f23004180016b22032400200341e0006a10242202200041e8006a220129030010331026200220012903001030200228020c200241106a28020047044010000b2002280204210520022802002106200341286a102421012000290370103321092001200341106a1034220410352001200920042802046a20042802006b10262001200029037010300240200128020c200141106a280200460440200141046a2109200128020021070c010b200141046a2109100020012802002107200128020c2001280210460d0010000b2006200520072009280200100b200428020022050440200420053602040b200128020c22040440200120043602100b200228020c22010440200220013602100b200341e0006a10242201200041c8006a220229030010331026200120022903001030200041d0006a2105200128020c200141106a28020047044010000b2001280204210620012802002109200341286a102421022005102521072002200341106a1034220410352002200720042802046a20042802006b102602402002200341d0006a200510141027220228020c200241106a280200460440200241046a2105200228020021070c010b200241046a2105100020022802002107200228020c2002280210460d0010000b2009200620072005280200100b200428020022050440200420053602040b200228020c22040440200220043602100b200128020c22020440200120023602100b200341286a10242202200029031810331026200220002903181030200228020c200241106a28020047044010000b2002280204210920022802002107200341106a1024210141002106200341f8006a4100360200200341f0006a4200370300200341e8006a420037030020034200370360200341e0006a41001036200341e0006a200341d0006a200041206a2205101410372204200041306a29030010382004410110362003280260210a200441046a1039200120031034220410352001200a20042802046a20042802006b10262001280204210a0240200141106a2802002208200141146a280200220b4904402008200aad4220864202843702002001200128021041086a3602100c010b2008200128020c220c6b410375220841016a220d200b200c6b220b410275220c200c200d491b41ffffffff01200b41037541ffffffff00491b220b0440200b410374102f21060b200620084103746a2208200aad42208642028437020020082001280210200128020c220d6b220a6b210c2006200b4103746a2106200841086a2108200a41014e0440200c200d200a103a1a0b20012006360214200120083602102001200c36020c0b200341f8006a4100360200200341f0006a4200370300200341e8006a420037030020034200370360200341e0006a200341d0006a2005101410372206200029033010382001200328026010262001200341406b200510141027220520002903301030200641046a10390240200528020c2001280210460440200528020021060c010b100020052802002106200528020c2001280210460d0010000b2007200920062001280204100b200428020022060440200420063602040b200528020c22040440200120043602100b200228020c22010440200220013602100b20034180016a24000b0e002000101f410147044010000b0b2900200041003602082000420037020020004100103b200041146a41003602002000420037020c20000b5801027f230041306b22012400200141286a4100360200200141206a4200370300200141186a420037030020014200370310200141106a2001200010141037210020012802102102200041046a1039200141306a240020020b13002000280208200149044020002001103b0b0b4e01037f20002001280208200141016a20012d0000220241017122031b22042001280204200241017620031b22011003200028020422026a103c20042001200220002802006a10042000103d20000b880101037f41bc08410136020041c0082802002100034020000440034041c40841c4082802002201417f6a2202360200200141014845044041bc084100360200200020024102746a22004184016a280200200041046a28020011020041bc08410136020041c00828020021000c010b0b41c408412036020041c008200028020022003602000c010b0b0b730020004200370210200042ffffffff0f370208200020023602042000200136020002402003410871450d002000104b20024f0d002003410471044010000c010b200042003702000b02402003411071450d002000104b20024d0d0020034104710440100020000f0b200042003702000b20000b4101017f200028020445044010000b0240200028020022012d0000418101470d00200028020441014d047f100020002802000520010b2c00014100480d0010000b0bd50101047f2001102e2204200128020422024b04401000200128020421020b200128020021052000027f02400240200204404100210120052c00002203417f4a0d01027f200341ff0171220141bf014d04404100200341ff017141b801490d011a200141c97e6a0c010b4100200341ff017141f801490d001a200141897e6a0b41016a21010c010b4101210120050d000c010b41002103200120046a20024b0d0020022001490d00410020022004490d011a200120056a2103200220016b20042004417f461b0c010b41000b360204200020033602000b2101017f2001102e220220012802044b044010000b200020012001104c2002104d0b2701017f230041206b22022400200241086a2000200141141029104b2100200241206a240020000bff0201037f200028020445044041000f0b2000102a41012102024020002802002c00002201417f4a0d00200141ff0171220341b7014d0440200341807f6a0f0b02400240200141ff0171220141bf014d0440024020002802042201200341c97e6a22024d047f100020002802040520010b4102490d0020002802002d00010d0010000b200241054f044010000b20002802002d000145044010000b4100210241b7012101034020012003460440200241384f0d030c0405200028020020016a41ca7e6a2d00002002410874722102200141016a21010c010b000b000b200141f7014d0440200341c07e6a0f0b024020002802042201200341897e6a22024d047f100020002802040520010b4102490d0020002802002d00010d0010000b200241054f044010000b20002802002d000145044010000b4100210241f701210103402001200346044020024138490d0305200028020020016a418a7e6a2d00002002410874722102200141016a21010c010b0b0b200241ff7d490d010b10000b20020b0b002000410120001b10180b2801017f2000420020011005200028020422026a103c42002001200220002802006a10062000103d0bfd0101067f024020002802042202200028020022046b220520014904402000280208220720026b200120056b22034f04400340200241003a00002000200028020441016a22023602042003417f6a22030d000c030b000b2001200720046b2202410174220420042001491b41ffffffff07200241ffffffff03491b220104402001102f21060b200520066a220521020340200241003a0000200241016a21022003417f6a22030d000b200120066a210420052000280204200028020022066b22016b2103200141014e0440200320062001103a1a0b2000200436020820002002360204200020033602000f0b200520014d0d002000200120046a3602040b0b3501017f2000200147044020002001280208200141016a20012d0000220041017122021b2001280204200041017620021b10131a0b0b4f01027f230041206b22012400200141186a4100360200200141106a4200370300200141086a4200370300200142003703002001200010382001280200210220014104721039200141206a240020020b3a01017f200041003602082000420037020020004101102f2201360200200141fe013a00002000200141016a22013602082000200136020420000b6101037f200028020c200041106a28020047044010000b200028020422022001280204200128020022036b22016a220420002802084b047f20002004103b20002802040520020b20002802006a20032001103a1a2000200028020420016a3602040bc10c02077f027e230041306b22042400200041046a2107024020014101460440200041086a280200200041146a280200200041186a22022802002203103f280200210120022003417f6a360200200710424180104f044020072000410c6a280200417c6a10410b200141384f047f2001103e20016a0520010b41016a2101200041186a2802002202450d01200041086a280200200041146a2802002002103f21000c010b0240200710420d00200041146a28020022014180084f0440200020014180786a360214200041086a2201280200220228020021032001200241046a360200200420033602182007200441186a10430c010b2000410c6a2802002202200041086a2802006b4102752203200041106a2205280200220620002802046b2201410275490440418020102f2105200220064704400240200028020c220120002802102202470d0020002802082203200028020422064b04402000200320012003200320066b41027541016a417e6d41027422026a1044220136020c2000200028020820026a3602080c010b200441186a200220066b2201410175410120011b22012001410276200041106a10452102200028020c210320002802082101034020012003470440200228020820012802003602002002200228020841046a360208200141046a21010c010b0b200029020421092000200229020037020420022009370200200029020c21092000200229020837020c2002200937020820021046200028020c21010b200120053602002000200028020c41046a36020c0c020b02402000280208220120002802042202470d00200028020c2203200028021022064904402000200120032003200620036b41027541016a41026d41027422026a104722013602082000200028020c20026a36020c0c010b200441186a200620026b2201410175410120011b2201200141036a410276200041106a10452102200028020c210320002802082101034020012003470440200228020820012802003602002002200228020841046a360208200141046a21010c010b0b200029020421092000200229020037020420022009370200200029020c21092000200229020837020c2002200937020820021046200028020821010b2001417c6a2005360200200020002802082201417c6a22023602082002280200210220002001360208200420023602182007200441186a10430c010b20042001410175410120011b2003200510452102418020102f2106024020022802082201200228020c2203470d0020022802042205200228020022084b04402002200520012005200520086b41027541016a417e6d41027422036a104422013602082002200228020420036a3602040c010b200441186a200320086b2201410175410120011b22012001410276200241106a280200104521032002280208210520022802042101034020012005470440200328020820012802003602002003200328020841046a360208200141046a21010c010b0b20022902002109200220032902003702002003200937020020022902082109200220032902083702082003200937020820031046200228020821010b200120063602002002200228020841046a360208200028020c2105034020002802082005460440200028020421012000200228020036020420022001360200200228020421012002200536020420002001360208200029020c21092000200229020837020c2002200937020820021046052005417c6a210502402002280204220120022802002203470d0020022802082206200228020c22084904402002200120062006200820066b41027541016a41026d41027422036a104722013602042002200228020820036a3602080c010b200441186a200820036b2201410175410120011b2201200141036a4102762002280210104521062002280208210320022802042101034020012003470440200428022020012802003602002004200428022041046a360220200141046a21010c010b0b20022902002109200220042903183702002002290208210a20022004290320370208200420093703182004200a37032020061046200228020421010b2001417c6a200528020036020020022002280204417c6a3602040c010b0b0b200441186a20071040200428021c4100360200200041186a2100410121010b2000200028020020016a360200200441306a24000ba10101037f41012103024002400240200128020420012d00002202410176200241017122041b220241014d0440200241016b0d032001280208200141016a20041b2c0000417f4c0d010c030b200241374b0d010b200241016a21030c010b2002103e20026a41016a21030b027f200041186a28020022010440200041086a280200200041146a2802002001103f0c010b20000b2201200128020020036a36020020000b880102027f017e4101210220014280015a044041002102034020012004845045044020044238862001420888842101200241016a2102200442088821040c010b0b200241384f047f2002103e20026a0520020b41016a21020b200041186a28020022030440200041086a280200200041146a2802002003103f21000b2000200028020020026a3602000bea0101047f230041106b22042400200028020422012000280210220241087641fcffff07716a2103027f410020012000280208460d001a2003280200200241ff07714102746a0b2101200441086a20001040200428020c210203400240200120024604402000410036021420002802082103200028020421010340200320016b41027522024103490d022000200141046a22013602040c000b000b200141046a220120032802006b418020470d0120032802042101200341046a21030c010b0b2002417f6a220241014d04402000418004418008200241016b1b3602100b200020011041200441106a24000bfc0801067f03400240200020046a2105200120046a210320022004460d002003410371450d00200520032d00003a0000200441016a21040c010b0b200220046b210602402005410371220745044003402006411049450440200020046a2203200120046a2205290200370200200341086a200541086a290200370200200441106a2104200641706a21060c010b0b027f2006410871450440200120046a2103200020046a0c010b200020046a2205200120046a2204290200370200200441086a2103200541086a0b21042006410471044020042003280200360200200341046a2103200441046a21040b20064102710440200420032f00003b0000200341026a2103200441026a21040b2006410171450d01200420032d00003a000020000f0b024020064120490d002007417f6a220741024b0d00024002400240024002400240200741016b0e020102000b2005200120046a220328020022073a0000200541016a200341016a2f00003b0000200041036a2108200220046b417d6a2106034020064111490d03200420086a2203200120046a220541046a2802002202410874200741187672360200200341046a200541086a2802002207410874200241187672360200200341086a2005410c6a28020022024108742007411876723602002003410c6a200541106a2802002207410874200241187672360200200441106a2104200641706a21060c000b000b2005200120046a220328020022073a0000200541016a200341016a2d00003a0000200041026a2108200220046b417e6a2106034020064112490d03200420086a2203200120046a220541046a2802002202411074200741107672360200200341046a200541086a2802002207411074200241107672360200200341086a2005410c6a28020022024110742007411076723602002003410c6a200541106a2802002207411074200241107672360200200441106a2104200641706a21060c000b000b2005200120046a28020022073a0000200041016a21082004417f7320026a2106034020064113490d03200420086a2203200120046a220541046a2802002202411874200741087672360200200341046a200541086a2802002207411874200241087672360200200341086a2005410c6a28020022024118742007410876723602002003410c6a200541106a2802002207411874200241087672360200200441106a2104200641706a21060c000b000b200120046a41036a2103200020046a41036a21050c020b200120046a41026a2103200020046a41026a21050c010b200120046a41016a2103200020046a41016a21050b20064110710440200520032d00003a00002005200328000136000120052003290005370005200520032f000d3b000d200520032d000f3a000f200541106a2105200341106a21030b2006410871044020052003290000370000200541086a2105200341086a21030b2006410471044020052003280000360000200541046a2105200341046a21030b20064102710440200520032f00003b0000200541026a2105200341026a21030b2006410171450d00200520032d00003a00000b20000b2f01017f200028020820014904402001101820002802002000280204103a210220002001360208200020023602000b0b3601017f200028020820014904402001101820002802002000280204103a210220002001360208200020023602000b200020013602040b7a01037f0340024020002802102201200028020c460d00200141786a2802004504401000200028021021010b200141786a22022002280200417f6a220336020020030d002000200236021020002001417c6a2802002201200028020420016b220210016a103c200120002802006a22012002200110020c010b0b0b1e01017f03402000044020004108762100200141016a21010c010b0b20010b25002000200120026a417f6a220241087641fcffff07716a280200200241ff07714102746a0b4f01037f20012802042203200128021020012802146a220441087641fcffff07716a21022000027f410020032001280208460d001a2002280200200441ff07714102746a0b360204200020023602000b2501017f200028020821020340200120024645044020002002417c6a22023602080c010b0b0b2801017f200028020820002802046b2201410874417f6a410020011b200028021420002802106a6b0ba10202057f017e230041206b22052400024020002802082202200028020c2203470d0020002802042204200028020022064b04402000200420022004200420066b41027541016a417e6d41027422036a104422023602082000200028020420036a3602040c010b200541086a200320066b2202410175410120021b220220024102762000410c6a10452103200028020821042000280204210203402002200446450440200328020820022802003602002003200328020841046a360208200241046a21020c010b0b20002902002107200020032902003702002003200737020020002902082107200020032902083702082003200737020820031046200028020821020b200220012802003602002000200028020841046a360208200541206a24000b2501017f200120006b220141027521032001044020022000200110480b200220034102746a0b4f01017f2000410036020c200041106a2003360200200104402001410274102f21040b200020043602002000200420024102746a22023602082000200420014102746a36020c2000200236020420000b2b01027f200028020821012000280204210203402001200247044020002001417c6a22013602080c010b0b0b1b00200120006b22010440200220016b22022000200110480b20020b8d0301037f024020002001460d00200120006b20026b410020024101746b4d0440200020012002103a1a0c010b20002001734103712103027f024020002001490440200020030d021a410021030340200120036a2105200020036a2204410371450440200220036b210241002103034020024104490d04200320046a200320056a280200360200200341046a21032002417c6a21020c000b000b20022003460d04200420052d00003a0000200341016a21030c000b000b024020030d002001417f6a21040340200020026a22034103714504402001417c6a21032000417c6a2104034020024104490d03200220046a200220036a2802003602002002417c6a21020c000b000b2002450d042003417f6a200220046a2d00003a00002002417f6a21020c000b000b2001417f6a210103402002450d03200020026a417f6a200120026a2d00003a00002002417f6a21020c000b000b200320056a2101200320046a0b210303402002450d01200320012d00003a00002002417f6a2102200341016a2103200141016a21010c000b000b0b3501017f230041106b220041e0880436020c41c808200028020c41076a417871220036020041cc08200036020041d0083f003602000b100020020440200020012002103a1a0b0b2e01017f200028020445044041000f0b4101210120002802002c0000417f4c047f2000104c2000102e6a0520010b0b5b00027f027f41002000280204450d001a410020002802002c0000417f4a0d011a20002802002d0000220041bf014d04404100200041b801490d011a200041c97e6a0c010b4100200041f801490d001a200041897e6a0b41016a0b0b5b01027f2000027f0240200128020022054504400c010b200220036a200128020422014b0d0020012002490d00410020012003490d011a200220056a2104200120026b20032003417f461b0c010b41000b360204200020043602000b0b4201004180080b3be5bca0e4b88900696e697400736574537472756374506572736f6e4100736574537472756374506572736f6e4200676574506572736f6e4e616d65";

    public static String BINARY = BINARY_0;

    public static final String FUNC_SETSTRUCTPERSONB = "setStructPersonB";

    public static final String FUNC_SETSTRUCTPERSONA = "setStructPersonA";

    public static final String FUNC_GETPERSONNAME = "getPersonName";

    protected ReferenceDataTypeStructContract(String contractAddress, Web3j web3j, Credentials credentials, GasProvider contractGasProvider, Long chainId) {
        super(BINARY, contractAddress, web3j, credentials, contractGasProvider, chainId);
    }

    protected ReferenceDataTypeStructContract(String contractAddress, Web3j web3j, TransactionManager transactionManager, GasProvider contractGasProvider, Long chainId) {
        super(BINARY, contractAddress, web3j, transactionManager, contractGasProvider, chainId);
    }

    public RemoteCall<TransactionReceipt> setStructPersonB() {
        final WasmFunction function = new WasmFunction(FUNC_SETSTRUCTPERSONB, Arrays.asList(), Void.class);
        return executeRemoteCallTransaction(function);
    }

    public RemoteCall<TransactionReceipt> setStructPersonB(BigInteger vonValue) {
        final WasmFunction function = new WasmFunction(FUNC_SETSTRUCTPERSONB, Arrays.asList(), Void.class);
        return executeRemoteCallTransaction(function, vonValue);
    }

    public static RemoteCall<ReferenceDataTypeStructContract> deploy(Web3j web3j, Credentials credentials, GasProvider contractGasProvider, Long chainId) {
        String encodedConstructor = WasmFunctionEncoder.encodeConstructor(BINARY, Arrays.asList());
        return deployRemoteCall(ReferenceDataTypeStructContract.class, web3j, credentials, contractGasProvider, encodedConstructor, chainId);
    }

    public static RemoteCall<ReferenceDataTypeStructContract> deploy(Web3j web3j, TransactionManager transactionManager, GasProvider contractGasProvider, Long chainId) {
        String encodedConstructor = WasmFunctionEncoder.encodeConstructor(BINARY, Arrays.asList());
        return deployRemoteCall(ReferenceDataTypeStructContract.class, web3j, transactionManager, contractGasProvider, encodedConstructor, chainId);
    }

    public static RemoteCall<ReferenceDataTypeStructContract> deploy(Web3j web3j, Credentials credentials, GasProvider contractGasProvider, BigInteger initialVonValue, Long chainId) {
        String encodedConstructor = WasmFunctionEncoder.encodeConstructor(BINARY, Arrays.asList());
        return deployRemoteCall(ReferenceDataTypeStructContract.class, web3j, credentials, contractGasProvider, encodedConstructor, initialVonValue, chainId);
    }

    public static RemoteCall<ReferenceDataTypeStructContract> deploy(Web3j web3j, TransactionManager transactionManager, GasProvider contractGasProvider, BigInteger initialVonValue, Long chainId) {
        String encodedConstructor = WasmFunctionEncoder.encodeConstructor(BINARY, Arrays.asList());
        return deployRemoteCall(ReferenceDataTypeStructContract.class, web3j, transactionManager, contractGasProvider, encodedConstructor, initialVonValue, chainId);
    }

    public RemoteCall<TransactionReceipt> setStructPersonA(String my_name, Uint64 my_age) {
        final WasmFunction function = new WasmFunction(FUNC_SETSTRUCTPERSONA, Arrays.asList(my_name,my_age), Void.class);
        return executeRemoteCallTransaction(function);
    }

    public RemoteCall<TransactionReceipt> setStructPersonA(String my_name, Uint64 my_age, BigInteger vonValue) {
        final WasmFunction function = new WasmFunction(FUNC_SETSTRUCTPERSONA, Arrays.asList(my_name,my_age), Void.class);
        return executeRemoteCallTransaction(function, vonValue);
    }

    public RemoteCall<String> getPersonName() {
        final WasmFunction function = new WasmFunction(FUNC_GETPERSONNAME, Arrays.asList(), String.class);
        return executeRemoteCall(function, String.class);
    }

    public static ReferenceDataTypeStructContract load(String contractAddress, Web3j web3j, Credentials credentials, GasProvider contractGasProvider, Long chainId) {
        return new ReferenceDataTypeStructContract(contractAddress, web3j, credentials, contractGasProvider, chainId);
    }

    public static ReferenceDataTypeStructContract load(String contractAddress, Web3j web3j, TransactionManager transactionManager, GasProvider contractGasProvider, Long chainId) {
        return new ReferenceDataTypeStructContract(contractAddress, web3j, transactionManager, contractGasProvider, chainId);
    }
}
