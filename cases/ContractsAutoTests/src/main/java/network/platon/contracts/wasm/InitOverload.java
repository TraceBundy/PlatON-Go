package network.platon.contracts.wasm;

import com.alaya.abi.wasm.WasmFunctionEncoder;
import com.alaya.abi.wasm.datatypes.WasmFunction;
import com.alaya.crypto.Credentials;
import com.alaya.protocol.Web3j;
import com.alaya.protocol.core.RemoteCall;
import com.alaya.protocol.core.methods.response.TransactionReceipt;
import com.alaya.rlp.wasm.datatypes.Uint64;
import com.alaya.rlp.wasm.datatypes.Uint8;
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
public class InitOverload extends WasmContract {
    private static String BINARY_0 = "0x0061736d0100000001530f60027f7f0060017f017f60017f0060037f7f7f017f60037f7f7f0060027f7f017f60000060047f7f7f7f017f60047f7f7f7f0060027f7e0060037e7e7f006000017f60017e017f60027e7e017f60017f017e02a9020d03656e760c706c61746f6e5f70616e6963000603656e760d726c705f6c6973745f73697a65000103656e760f706c61746f6e5f726c705f6c697374000403656e760e726c705f62797465735f73697a65000503656e7610706c61746f6e5f726c705f6279746573000403656e760d726c705f753132385f73697a65000d03656e760f706c61746f6e5f726c705f75313238000a03656e7617706c61746f6e5f6765745f696e7075745f6c656e677468000b03656e7610706c61746f6e5f6765745f696e707574000203656e7617706c61746f6e5f6765745f73746174655f6c656e677468000503656e7610706c61746f6e5f6765745f7374617465000703656e7610706c61746f6e5f7365745f7374617465000803656e760d706c61746f6e5f72657475726e00000342410600050002050700020101060103040201000e020102010100010c00090002000607010305030400020000030502000100020300000100030702030404060101080405017001010105030100020608017f0141d088040b073904066d656d6f72790200115f5f7761736d5f63616c6c5f63746f7273000d0f5f5f66756e63735f6f6e5f65786974002d06696e766f6b6500180aa958410400104a0b2401017f230041106b2202240020022001100f1a200041186a20021010200241106a24000ba10101037f20004200370200200041086a2202410036020020012d0000410171450440200020012902003702002002200141086a28020036020020000f0b20012802082103024020012802042201410a4d0440200020014101743a0000200041016a21020c010b200141106a4170712204101721022000200136020420002004410172360200200020023602080b2002200320011049200120026a41003a000020000bb00101037f230041206b22032400024020002802042202200028020849044020022001290200370200200241086a200141086a2802003602002001101120002000280204410c6a3602040c010b200341086a2000200220002802006b410c6d220241016a10122002200041086a1013220228020822042001290200370200200441086a200141086a2802003602002001101120022002280208410c6a360208200020021014200210150b200341206a24000b2201017f03402001410c470440200020016a4100360200200141046a21010c010b0b0b3101017f2001200028020820002802006b410c6d2200410174220220022001491b41d5aad5aa01200041aad5aad500491b0b4c01017f2000410036020c200041106a2003360200200104402001101621040b20002004360200200020042002410c6c6a2202360208200020042001410c6c6a36020c2000200236020420000baa0101037f200028020421022000280200210303402002200346450440200128020441746a2204200241746a2202290200370200200441086a200241086a280200360200200210112001200128020441746a3602040c010b0b200028020021022000200128020436020020012002360204200028020421022000200128020836020420012002360208200028020821022000200128020c3602082001200236020c200120012802043602000b2b01027f20002802082101200028020421020340200120024704402000200141746a22013602080c010b0b0b09002000410c6c10170b0b002000410120001b10190b950602057f017e230041a0016b22002400104a10072201101922031008200041206a200041086a20032001101a22024100101b200041206a101c02400240200041206a101d450d002000280224450d0020002802202d000041c001490d010b10000b20004180016a200041206a101e200028028401220141094f044010000b20002802800121030340200104402001417f6a210120033100002005420886842105200341016a21030c010b0b024002402005500d00418008101f200551044020021020200041206a102110220c020b418508101f2005510440200041d8006a1023210120021024410247044010000b200041206a20024101101b200041206a20011025200041206a10212103200041206a20004180016a2001100f100e200310220c020b419008101f200551044020021020200041206a102121032000413c6a28020021022000280238210420004180016a10262201200220046b410c6dad220510271028200120051029200128020c200141106a28020047044010000b20012802002001280204100c200128020c22020440200120023602100b200310220c020b41a008101f2005520d0020021024410247044010000b200041206a20024101101b200041206a101c02400240200041206a101d450d002000280224450d0020002802202d000041c001490d010b10000b20004180016a200041206a101e200028028401220141024f044010000b4100210220002802800121030340200104402001417f6a210120032d00002102200341016a21030c010b0b200041206a10212103200041c8006a200041206a280218200241ff0171410c6c6a100f1a200041d8006a1026210120004198016a410036020020004190016a420037030020004188016a4200370300200042003703800120004180016a200041f0006a200041c8006a100f102a200028028001210220004180016a410472102b200120021028200120004180016a200041c8006a100f102c200128020c200141106a28020047044010000b20012802002001280204100c200128020c22020440200120023602100b200310220c010b10000b102d200041a0016a24000b9b0101047f230041106b220124002001200036020c2000047f41c008200041086a2202411076220041c0082802006a220336020041bc0841bc08280200220420026a41076a417871220236020002400240200341107420024d044041c008200341016a360200200041016a21000c010b2000450d010b200040000d0010000b20042001410c6a4104103841086a0541000b2100200141106a240020000b0c00200020012002411c102e0bc90202067f017e230041106b220324002001280208220520024b0440200341086a2001103b20012003280208200328020c103136020c20032001103b410021052001027f410020032802002207450d001a410020032802042208200128020c2206490d001a200820062006417f461b210420070b360210200141146a2004360200200141003602080b200141106a210603402001280214210402402005200249044020040d01410021040b2000200628020020044114102e1a200341106a24000f0b20032001103b41002104027f410020032802002205450d001a410020032802042208200128020c2207490d001a200820076b2104200520076a0b21052001200436021420012005360210200320064100200520041031104d2001200329030022093702102001200128020c2009422088a76a36020c2001200128020841016a22053602080c000b000b4101017f200028020445044010000b0240200028020022012d0000418101470d00200028020441014d047f100020002802000520010b2c00014100480d0010000b0b980101037f200028020445044041000f0b2000101c200028020022022c0000220141004e044020014100470f0b027f4101200141807f460d001a200141ff0171220341b7014d0440200028020441014d047f100020002802000520020b2d00014100470f0b4100200341bf014b0d001a2000280204200141ff017141ca7e6a22014d047f100020002802000520020b20016a2d00004100470b0bd50101047f2001102f2204200128020422024b04401000200128020421020b200128020021052000027f02400240200204404100210120052c00002203417f4a0d01027f200341ff0171220141bf014d04404100200341ff017141b801490d011a200141c97e6a0c010b4100200341ff017141f801490d001a200141897e6a0b41016a21010c010b4101210120050d000c010b41002103200120046a20024b0d0020022001490d00410020022004490d011a200120056a2103200220016b20042004417f461b0c010b41000b360204200020033602000b3901027e42a5c688a1c89ca7f94b210103402000300000220250450440200041016a2100200142b383808080207e20028521010c010b0b20010b0e0020001024410147044010000b0b9006010a7f23004190016b2204240020004200370218200042aebed3dfedeebab3583703102000410036020820004200370200200041206a4100360200200441186a1026220620002903101029200628020c200641106a28020047044010000b200041186a21080240200628020022032006280204220510092207450d002007101721020340200120026a41003a00002007200141016a2201470d000b2003200520022001100a417f460440410021010c010b024002402004200241016a200120026a2002417f736a101a2202280204450d0020022802002d000041c001490d002002102421012000280220200028021822036b410c6d20014904402008200441f8006a2001200028021c20036b410c6d200041206a101322011014200110150b200441e8006a2002410110302101200441d8006a200241001030210520012802042102034020052802042002464100200128020822032005280208461b0d02200441406b20022003411c102e2102200441306a10232103200441f8006a20024100101b200441f8006a200310252008200441306a101020012001280204220220012802086a410020021b22023602042001280200220304402001200336020820022003103121092001027f2001280204220a4504404100210341000c010b410021034100200128020822022009490d001a200220092009417f461b2103200a0b2202ad2003ad42208684370204200141002001280200220920036b2203200320094b1b3602000c0105200141003602080c010b000b000b10000b200721010b200628020c22020440200620023602100b024020010d002000411c6a210220002802042203200028020022076b410c6d22052000280220200028021822016b410c6d4d04402005200228020020016b410c6d22064b0440200720072006410c6c6a2205200110321a20052003200210330c020b2008200720032001103210340c010b200104402008103520004100360220200042003702180b20002008200510122205101622013602182000200136021c200020012005410c6c6a36022020072003200210330b20044190016a240020000bf804010a7f230041f0006b22012400200141186a10262204200029031010271028200420002903101029200428020c200441106a28020047044010000b200428020421092004280200210a200110262103200141e8006a4100360200200141e0006a4200370300200141d8006a420037030020014200370350027f20002802182000411c6a2802004604402001410136025041010c010b200141d0006a41001036200028021c210520002802182102037f2002200546047f200141d0006a41011036200128025005200141d0006a41001036200141d0006a200141406b2002100f102a200141d0006a410110362002410c6a21020c010b0b0b2106200141d0006a410472102b41011017220241fe013a0000200328020c200341106a28020047044010000b200241016a21072003280204220541016a220820032802084b047f20032008103720032802040520050b20032802006a2002410110381a2003200328020441016a3602042003200620026b20076a10282003200028021c20002802186b410c6d10392107200141d0006a4104722108200028021c210620002802182102034020022006470440200741011039210520014100360268200142003703602001420037035820014200370350200141d0006a200141406b2002100f102a2005200128025010282005200141306a2002100f102c2008102b2002410c6a21020c010b0b0240200328020c2003280210460440200328020021020c010b100020032802002102200328020c2003280210460d0010000b200a200920022003280204100b200328020c22020440200320023602100b200428020c22020440200420023602100b200041186a103a2000103a200141f0006a24000b190020004200370200200041086a41003602002000101120000b800101047f230041106b2201240002402000280204450d0020002802002d000041c001490d00200141086a2000103b200128020c210003402000450d01200141002001280208220320032000103122046a20034520002004497222031b3602084100200020046b20031b2100200241016a21020c000b000b200141106a240020020bf40201057f230041206b22022400024002402000280204044020002802002d000041c001490d010b200241086a10231a0c010b200241186a2000101e2000102f21030240024002400240200228021822000440200228021c220520034f0d010b41002100200241106a410036020020024200370308410021050c010b200241106a4100360200200242003703082000200520032003417f461b22046a21052004410a4b0d010b200220044101743a0008200241086a41017221030c010b200441106a4170712206101721032002200436020c20022006410172360208200220033602100b03402000200546450440200320002d00003a0000200341016a2103200041016a21000c010b0b200341003a00000b024020012d0000410171450440200141003b01000c010b200128020841003a00002001410036020420012d0000410171450d00200141003602000b20012002290308370200200141086a200241106a280200360200200241086a1011200241206a24000b29002000410036020820004200370200200041001037200041146a41003602002000420037020c20000b990102037f017e230041206b22012400200141186a4100360200200141106a4200370300200141086a4200370300200142003703004101210320004280015a0440034020002004845045044020044238862000420888842100200241016a2102200442088821040c010b0b200241384f047f2002103c20026a0520020b41016a21030b200120033602002001410472102b200141206a240020030b1300200028020820014904402000200110370b0b2801017f2000420020011005200028020422026a103d42002001200220002802006a10062000103e0b9a0101037f41012103024002400240200128020420012d00002202410176200241017122041b220241014d0440200241016b0d032001280208200141016a20041b2c0000417f4c0d010c030b200241374b0d010b200241016a21030c010b2002103c20026a41016a21030b200041186a28020022010440200041086a280200200041146a2802002001103f21000b2000200028020020036a3602000bea0101047f230041106b22042400200028020422012000280210220241087641fcffff07716a2103027f410020012000280208460d001a2003280200200241ff07714102746a0b2101200441086a20001040200428020c210203400240200120024604402000410036021420002802082103200028020421010340200320016b41027522024103490d022000200141046a22013602040c000b000b200141046a220120032802006b418020470d0120032802042101200341046a21030c010b0b2002417f6a220241014d04402000418004418008200241016b1b3602100b200020011041200441106a24000b4c01037f20002001280208200141016a20012d0000220241017122031b22042001280204200241017620031b22011003200028020422026a103d20042001200220002802006a10042000103e0b880101037f41ac08410136020041b0082802002100034020000440034041b40841b4082802002201417f6a2202360200200141014845044041ac084100360200200020024102746a22004184016a280200200041046a28020011020041ac08410136020041b00828020021000c010b0b41b408412036020041b008200028020022003602000c010b0b0b730020004200370210200042ffffffff0f370208200020023602042000200136020002402003410871450d002000104b20024f0d002003410471044010000c010b200042003702000b02402003411071450d002000104b20024d0d0020034104710440100020000f0b200042003702000b20000bff0201037f200028020445044041000f0b2000101c41012102024020002802002c00002201417f4a0d00200141ff0171220341b7014d0440200341807f6a0f0b02400240200141ff0171220141bf014d0440024020002802042201200341c97e6a22024d047f100020002802040520010b4102490d0020002802002d00010d0010000b200241054f044010000b20002802002d000145044010000b4100210241b7012101034020012003460440200241384f0d030c0405200028020020016a41ca7e6a2d00002002410874722102200141016a21010c010b000b000b200141f7014d0440200341c07e6a0f0b024020002802042201200341897e6a22024d047f100020002802040520010b4102490d0020002802002d00010d0010000b200241054f044010000b20002802002d000145044010000b4100210241f701210103402001200346044020024138490d0305200028020020016a418a7e6a2d00002002410874722102200141016a21010c010b0b0b200241ff7d490d010b10000b20020be70101037f230041106b2204240020004200370200200041086a410036020020012802042103024002402002450440200321020c010b410021022003450d002003210220012802002d000041c001490d00200441086a2001103b20004100200428020c2201200428020822022001103122032003417f461b20024520012003497222031b220536020820004100200220031b3602042000200120056b3602000c010b20012802002103200128020421012000410036020020004100200220016b20034520022001497222021b36020820004100200120036a20021b3602040b200441106a240020000b2701017f230041206b22022400200241086a200020014114102e104b2100200241206a240020000bd00201077f200120006b2108410021010340200120026a2105200120084645044002402005200020016a2203460d00200341046a28020020032d00002204410176200441017122071b2104200341016a2106200341086a2802002109410a21032009200620071b210720052d0000410171220604402005280200417e71417f6a21030b200420034d0440027f20060440200541086a2802000c010b200541016a0b21032004044020032007200410480b200320046a41003a000020052d00004101710440200541046a20043602000c020b200520044101743a00000c010b416f2106200341e6ffffff074d0440410b20034101742203200420042003491b220341106a4170712003410b491b21060b200610172203200720041049200541046a200436020020052006410172360200200541086a2003360200200320046a41003a00000b2001410c6a21010c010b0b20050b2e000340200020014645044020022802002000100f1a20022002280200410c6a3602002000410c6a21000c010b0b0b0900200020013602040b0b002000200028020010340bc10c02077f027e230041306b22042400200041046a2107024020014101460440200041086a280200200041146a280200200041186a22022802002203103f280200210120022003417f6a360200200710424180104f044020072000410c6a280200417c6a10410b200141384f047f2001103c20016a0520010b41016a2101200041186a2802002202450d01200041086a280200200041146a2802002002103f21000c010b0240200710420d00200041146a28020022014180084f0440200020014180786a360214200041086a2201280200220228020021032001200241046a360200200420033602182007200441186a10430c010b2000410c6a2802002202200041086a2802006b4102752203200041106a2205280200220620002802046b220141027549044041802010172105200220064704400240200028020c220120002802102202470d0020002802082203200028020422064b04402000200320012003200320066b41027541016a417e6d41027422026a1044220136020c2000200028020820026a3602080c010b200441186a200220066b2201410175410120011b22012001410276200041106a10452102200028020c210320002802082101034020012003470440200228020820012802003602002002200228020841046a360208200141046a21010c010b0b200029020421092000200229020037020420022009370200200029020c21092000200229020837020c2002200937020820021046200028020c21010b200120053602002000200028020c41046a36020c0c020b02402000280208220120002802042202470d00200028020c2203200028021022064904402000200120032003200620036b41027541016a41026d41027422026a104722013602082000200028020c20026a36020c0c010b200441186a200620026b2201410175410120011b2201200141036a410276200041106a10452102200028020c210320002802082101034020012003470440200228020820012802003602002002200228020841046a360208200141046a21010c010b0b200029020421092000200229020037020420022009370200200029020c21092000200229020837020c2002200937020820021046200028020821010b2001417c6a2005360200200020002802082201417c6a22023602082002280200210220002001360208200420023602182007200441186a10430c010b20042001410175410120011b200320051045210241802010172106024020022802082201200228020c2203470d0020022802042205200228020022084b04402002200520012005200520086b41027541016a417e6d41027422036a104422013602082002200228020420036a3602040c010b200441186a200320086b2201410175410120011b22012001410276200241106a280200104521032002280208210520022802042101034020012005470440200328020820012802003602002003200328020841046a360208200141046a21010c010b0b20022902002109200220032902003702002003200937020020022902082109200220032902083702082003200937020820031046200228020821010b200120063602002002200228020841046a360208200028020c2105034020002802082005460440200028020421012000200228020036020420022001360200200228020421012002200536020420002001360208200029020c21092000200229020837020c2002200937020820021046052005417c6a210502402002280204220120022802002203470d0020022802082206200228020c22084904402002200120062006200820066b41027541016a41026d41027422036a104722013602042002200228020820036a3602080c010b200441186a200820036b2201410175410120011b2201200141036a4102762002280210104521062002280208210320022802042101034020012003470440200428022020012802003602002004200428022041046a360220200141046a21010c010b0b20022902002109200220042903183702002002290208210a20022004290320370208200420093703182004200a37032020061046200228020421010b2001417c6a200528020036020020022002280204417c6a3602040c010b0b0b200441186a20071040200428021c4100360200200041186a2100410121010b2000200028020020016a360200200441306a24000b2f01017f2000280208200149044020011019200028020020002802041038210220002001360208200020023602000b0bfc0801067f03400240200020046a2105200120046a210320022004460d002003410371450d00200520032d00003a0000200441016a21040c010b0b200220046b210602402005410371220745044003402006411049450440200020046a2203200120046a2205290200370200200341086a200541086a290200370200200441106a2104200641706a21060c010b0b027f2006410871450440200120046a2103200020046a0c010b200020046a2205200120046a2204290200370200200441086a2103200541086a0b21042006410471044020042003280200360200200341046a2103200441046a21040b20064102710440200420032f00003b0000200341026a2103200441026a21040b2006410171450d01200420032d00003a000020000f0b024020064120490d002007417f6a220741024b0d00024002400240024002400240200741016b0e020102000b2005200120046a220328020022073a0000200541016a200341016a2f00003b0000200041036a2108200220046b417d6a2106034020064111490d03200420086a2203200120046a220541046a2802002202410874200741187672360200200341046a200541086a2802002207410874200241187672360200200341086a2005410c6a28020022024108742007411876723602002003410c6a200541106a2802002207410874200241187672360200200441106a2104200641706a21060c000b000b2005200120046a220328020022073a0000200541016a200341016a2d00003a0000200041026a2108200220046b417e6a2106034020064112490d03200420086a2203200120046a220541046a2802002202411074200741107672360200200341046a200541086a2802002207411074200241107672360200200341086a2005410c6a28020022024110742007411076723602002003410c6a200541106a2802002207411074200241107672360200200441106a2104200641706a21060c000b000b2005200120046a28020022073a0000200041016a21082004417f7320026a2106034020064113490d03200420086a2203200120046a220541046a2802002202411874200741087672360200200341046a200541086a2802002207411874200241087672360200200341086a2005410c6a28020022024118742007410876723602002003410c6a200541106a2802002207411874200241087672360200200441106a2104200641706a21060c000b000b200120046a41036a2103200020046a41036a21050c020b200120046a41026a2103200020046a41026a21050c010b200120046a41016a2103200020046a41016a21050b20064110710440200520032d00003a00002005200328000136000120052003290005370005200520032f000d3b000d200520032d000f3a000f200541106a2105200341106a21030b2006410871044020052003290000370000200541086a2105200341086a21030b2006410471044020052003280000360000200541046a2105200341046a21030b20064102710440200520032f00003b0000200541026a2105200341026a21030b2006410171450d00200520032d00003a00000b20000b9d0201057f2001044020002802042105200041106a2802002202200041146a280200220349044020022001ad2005ad422086843702002000200028021041086a36021020000f0b027f41002002200028020c22046b410375220641016a2202200320046b2203410275220420042002491b41ffffffff01200341037541ffffffff00491b2204450d001a200441037410170b2102200220064103746a22032001ad2005ad4220868437020020032000280210200028020c22066b22016b2105200220044103746a2102200341086a2103200141014e044020052006200110381a0b20002002360214200020033602102000200536020c20000f0b200041001001200028020422016a103d41004100200120002802006a10022000103e20000b0e0020002802000440200010350b0b2101017f2001102f220220012802044b044010000b200020012001104c2002104d0b1e01017f03402000044020004108762100200141016a21010c010b0b20010b3601017f2000280208200149044020011019200028020020002802041038210220002001360208200020023602000b200020013602040b7a01037f0340024020002802102201200028020c460d00200141786a2802004504401000200028021021010b200141786a22022002280200417f6a220336020020030d002000200236021020002001417c6a2802002201200028020420016b220210016a103d200120002802006a22012002200110020c010b0b0b25002000200120026a417f6a220241087641fcffff07716a280200200241ff07714102746a0b4f01037f20012802042203200128021020012802146a220441087641fcffff07716a21022000027f410020032001280208460d001a2002280200200441ff07714102746a0b360204200020023602000b2501017f200028020821020340200120024645044020002002417c6a22023602080c010b0b0b2801017f200028020820002802046b2201410874417f6a410020011b200028021420002802106a6b0ba10202057f017e230041206b22052400024020002802082202200028020c2203470d0020002802042204200028020022064b04402000200420022004200420066b41027541016a417e6d41027422036a104422023602082000200028020420036a3602040c010b200541086a200320066b2202410175410120021b220220024102762000410c6a10452103200028020821042000280204210203402002200446450440200328020820022802003602002003200328020841046a360208200241046a21020c010b0b20002902002107200020032902003702002003200737020020002902082107200020032902083702082003200737020820031046200028020821020b200220012802003602002000200028020841046a360208200541206a24000b2501017f200120006b220141027521032001044020022000200110480b200220034102746a0b4f01017f2000410036020c200041106a2003360200200104402001410274101721040b200020043602002000200420024102746a22023602082000200420014102746a36020c2000200236020420000b2b01027f200028020821012000280204210203402001200247044020002001417c6a22013602080c010b0b0b1b00200120006b22010440200220016b22022000200110480b20020b8d0301037f024020002001460d00200120006b20026b410020024101746b4d044020002001200210381a0c010b20002001734103712103027f024020002001490440200020030d021a410021030340200120036a2105200020036a2204410371450440200220036b210241002103034020024104490d04200320046a200320056a280200360200200341046a21032002417c6a21020c000b000b20022003460d04200420052d00003a0000200341016a21030c000b000b024020030d002001417f6a21040340200020026a22034103714504402001417c6a21032000417c6a2104034020024104490d03200220046a200220036a2802003602002002417c6a21020c000b000b2002450d042003417f6a200220046a2d00003a00002002417f6a21020c000b000b2001417f6a210103402002450d03200020026a417f6a200120026a2d00003a00002002417f6a21020c000b000b200320056a2101200320046a0b210303402002450d01200320012d00003a00002002417f6a2102200341016a2103200141016a21010c000b000b0b10002002044020002001200210381a0b0b3501017f230041106b220041d0880436020c41b808200028020c41076a417871220036020041bc08200036020041c0083f003602000b2e01017f200028020445044041000f0b4101210120002802002c0000417f4c047f2000104c2000102f6a0520010b0b5b00027f027f41002000280204450d001a410020002802002c0000417f4a0d011a20002802002d0000220041bf014d04404100200041b801490d011a200041c97e6a0c010b4100200041f801490d001a200041897e6a0b41016a0b0b5b01027f2000027f0240200128020022054504400c010b200220036a200128020422014b0d0020012002490d00410020012003490d011a200220056a2104200120026b20032003417f461b0c010b41000b360204200020043602000b0b3101004180080b2a696e6974006164645f766563746f72006765745f766563746f725f73697a65006765745f766563746f72";

    public static String BINARY = BINARY_0;

    public static final String FUNC_ADD_VECTOR = "add_vector";

    public static final String FUNC_GET_VECTOR_SIZE = "get_vector_size";

    public static final String FUNC_GET_VECTOR = "get_vector";

    protected InitOverload(String contractAddress, Web3j web3j, Credentials credentials, GasProvider contractGasProvider, Long chainId) {
        super(BINARY, contractAddress, web3j, credentials, contractGasProvider, chainId);
    }

    protected InitOverload(String contractAddress, Web3j web3j, TransactionManager transactionManager, GasProvider contractGasProvider, Long chainId) {
        super(BINARY, contractAddress, web3j, transactionManager, contractGasProvider, chainId);
    }

    public static RemoteCall<InitOverload> deploy(Web3j web3j, Credentials credentials, GasProvider contractGasProvider, Long chainId) {
        String encodedConstructor = WasmFunctionEncoder.encodeConstructor(BINARY, Arrays.asList());
        return deployRemoteCall(InitOverload.class, web3j, credentials, contractGasProvider, encodedConstructor, chainId);
    }

    public static RemoteCall<InitOverload> deploy(Web3j web3j, TransactionManager transactionManager, GasProvider contractGasProvider, Long chainId) {
        String encodedConstructor = WasmFunctionEncoder.encodeConstructor(BINARY, Arrays.asList());
        return deployRemoteCall(InitOverload.class, web3j, transactionManager, contractGasProvider, encodedConstructor, chainId);
    }

    public static RemoteCall<InitOverload> deploy(Web3j web3j, Credentials credentials, GasProvider contractGasProvider, BigInteger initialVonValue, Long chainId) {
        String encodedConstructor = WasmFunctionEncoder.encodeConstructor(BINARY, Arrays.asList());
        return deployRemoteCall(InitOverload.class, web3j, credentials, contractGasProvider, encodedConstructor, initialVonValue, chainId);
    }

    public static RemoteCall<InitOverload> deploy(Web3j web3j, TransactionManager transactionManager, GasProvider contractGasProvider, BigInteger initialVonValue, Long chainId) {
        String encodedConstructor = WasmFunctionEncoder.encodeConstructor(BINARY, Arrays.asList());
        return deployRemoteCall(InitOverload.class, web3j, transactionManager, contractGasProvider, encodedConstructor, initialVonValue, chainId);
    }

    public RemoteCall<TransactionReceipt> add_vector(String one_name) {
        final WasmFunction function = new WasmFunction(FUNC_ADD_VECTOR, Arrays.asList(one_name), Void.class);
        return executeRemoteCallTransaction(function);
    }

    public RemoteCall<TransactionReceipt> add_vector(String one_name, BigInteger vonValue) {
        final WasmFunction function = new WasmFunction(FUNC_ADD_VECTOR, Arrays.asList(one_name), Void.class);
        return executeRemoteCallTransaction(function, vonValue);
    }

    public RemoteCall<Uint64> get_vector_size() {
        final WasmFunction function = new WasmFunction(FUNC_GET_VECTOR_SIZE, Arrays.asList(), Uint64.class);
        return executeRemoteCall(function, Uint64.class);
    }

    public RemoteCall<String> get_vector(Uint8 index) {
        final WasmFunction function = new WasmFunction(FUNC_GET_VECTOR, Arrays.asList(index), String.class);
        return executeRemoteCall(function, String.class);
    }

    public static InitOverload load(String contractAddress, Web3j web3j, Credentials credentials, GasProvider contractGasProvider, Long chainId) {
        return new InitOverload(contractAddress, web3j, credentials, contractGasProvider, chainId);
    }

    public static InitOverload load(String contractAddress, Web3j web3j, TransactionManager transactionManager, GasProvider contractGasProvider, Long chainId) {
        return new InitOverload(contractAddress, web3j, transactionManager, contractGasProvider, chainId);
    }
}
