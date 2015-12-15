<?php
// passchk.php is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the
// Free Software Foundation; either version 3 of the License, or (at your
// option) any later version.
//
// passchk.php is distributed in the hope that it will be useful but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// The passchk.php archive has a copy of the GNU General Public License,
// but if you did not get it, see <http://www.gnu.org/licenses/>
//
// This is a copy of the original JavaScript project called passchk.js.
// passchk.js is available from http://rumkin.com/tools/password/passchk.php
// That said - this PHP version is missing the following functions:
// * Parse_Common_Word()
// * Parse_Common()
// * CheckIfLoaded()
//
// As well, these functions have hard codded results as their return values
// never change:
// * Parse_Frequency_Token()
// * Parse_Frequency()
//
// This port of the original js library tries to stay true to the math and resulting
// entropy calculations, but currently is a bit off in it's results.  As well, it returns
// the simple entropy calculation of entropy = n * lg(c) (see https://blogs.dropbox.com/tech/2012/04/zxcvbn-realistic-password-strength-estimation/).  Finally, it also
// returns time to crack info based on 350 billion guesses sec. This later info can be used
// safely server side to set the expire date of a user password.  This avoids the need
// to use the original passchk.js client side and trust the user editable POST value from a form
//
// php functions for the password checker form

class passchk {

    var $tokenCounts = array();
	var $Frequency_Table = array();
	var $Frequency_List = null;
    var $min_days_valid = 0.00000454861;
    var $min_days_labels = '1 second';

	/**
	 * defunct! - place holder from passchk.js
	 * @return bool false
	 */
	public function Parse_Common_Word(){
		return false;
	}

	/**
	 * defunct! - place holder from passchk.js
	 * @return bool false
	 */
	public function Parse_Common(){
		return false;
	}

    /**
     * defunct - see $this->getFrequencyTable()
     * @return bool false
     */
	public function Parse_Frequency_Token(){
        return false;
	}

	/**
	 * defunct - see $this->getFrequencyTable()
	 * @return bool false
	 */
	function Parse_Frequency(){
        return false;
	}

    /**
     * Check the lowercase value against a-z and run hexdec(bin2hex($c)) - hexdec(bin2hex('a')) + 1
     * @param $c
     * @return int
     */
	function Get_Index($c) {
		$c = strtolower($c{0});
		$strPos = strpos('abcdefghijklmnopqrstuvwxyz', $c);
		if ($strPos === false || $strPos < 0 || $strPos > 26) {
			return 0;
		} else {
			//charCodeAt() == hexdec(bin2hex($char))    THANKS:
			// http://stackoverflow.com/questions/15457412/javascript-to-php-domain-charcodeati
			return hexdec(bin2hex($c)) - hexdec(bin2hex('a')) + 1;
		}
	}

    /**
     * Get the character space.  if the password is 'a' or 'aaaaa' this will return 26.
     * When you add another character from a different space, you get more points.  So 'aA'
     * will return 52
     *
     * @param $pass
     * @return int
     */
	function Get_Charset_Size($pass){
		$a = false;
		$u = false;
		$n = false;
		$ns = false;
		$r = false;
		$sp = false;
		$s = false;
		$chars = 0;
		$passAry = str_split($pass);

		foreach ($passAry as $key => $c) {
			if (!$a && strpos('abcdefghijklmnopqrstuvwxyz', $c)  !== false) {
				$chars += 26;
				$a = true;
			}
			if (!$u && strpos('ABCDEFGHIJKLMNOPQRSTUVWXYZ', $c)  !== false) {
				$chars += 26;
				$u = true;
			}
			if (!$n && strpos('0123456789', $c)  !== false) {
				$chars += 10;
				$n = true;
			}
			if (!$ns && strpos('!@#$%^&*()', $c)  !== false) {
				$chars += 10;
				$ns = true;
			}
			if (!$r && strpos("`~-_=+[{]}\\|;:'\",<.>/?", $c) !== false) {
				$chars += 20;
				$r = true;
			}
			if (!$sp && $c == ' '){
				$chars += 1;
				$sp = true;
			}
			if (!$s && ($c < ' ' || $c > '~')) {
				$chars += 32 + 128;
				$s = true;
			}
		}

		return $chars;
	}

	/**
	 * defunct - place holder from passchk.js
	 * @param $s
	 * @return bool false
	 */
	function Set_Text($s){
		return false;
	}

    /**
     * Given a password calculate the bits of entropy and other related information. uses
     * bcmath functions for float accuracy where applicable.
     * @param $password str
     * @return array $results
     */
    public function ShowStats($password) {
        // init stuffs and set bc math accuracy to 16
        bcscale(16);
        $results = array();
        $length = strlen($password);
        $bits = 0;
        $charSet = 0;
        $plower = strtolower($password);
        $log2 = log(2);
        $c = NULL;
        $simpleBits = 0;

        if ($length > 1){
			$this->Frequency_Table = $this->getFrequencyTable();
            $charSet = bcdiv(log($this->Get_Charset_Size($password)) , $log2);
            $aidx = $this->Get_Index($plower{0});
			$plowerAry = str_split($plower);
            $simpleBits = $length * log($this->Get_Charset_Size($password));
			foreach($plowerAry as $key => $b){
                $bidx = $this->Get_Index($b);
                $c = bcsub(1.0, $this->Frequency_Table[bcadd(bcmul($aidx,27), $bidx,0)]);
                $bits = bcadd(bcmul(bcmul($charSet, $c), $c), $bits);  // Squared = assume they are good guessers
                $aidx = $bidx;
            }
        }

        // figure simple entropy and get related info, if any
        $ttcAry = $this->getRelatedBitData($bits);

        // push everything into our results array
        $results['length'] = $length;
        $results['time_to_crack'] = $ttcAry['time_to_crack'];
        $results['valid'] = $ttcAry['valid'];
        $results['days'] = $ttcAry['days'];
        $results['simple_bits'] = round($simpleBits,2);
        // TODO - $bits don't quite match passchk.js's - float inaccuracy? bcmath didn't seem to fix...
        $results['bits'] = round($bits,2);

        return $results;
    }

	/**
	 * deprecated! - place holder from passchk.js
	 * @return bool false
	 */
	public function CheckIfLoaded(){
		return false;
	}

	/**
	 * helper function to look up the pre-calculated time to
	 * crack, days valid and readable days valid based on entropy bits
	 * @param $bits
	 * @return array|mixed
	 */
    public function getRelatedBitData($bits){

        $bits = round($bits, 0, PHP_ROUND_HALF_DOWN);
        $entropyAry = $this->getEntropyArray();
        if (isset($entropyAry[$bits])){
            $return = $entropyAry[$bits];
        } elseif (sizeof($entropyAry) < $bits){
            $return = array('days' => '138949', 'time_to_crack' => '380+ Years', 'valid' => '380 Years');
        } else {
            $return = array('days' => 0, 'time_to_crack' => 'NA', 'valid' => 'NA');
        }
        return $return;
    }


    /**
     * pre-calculated array taken from passchk.js. this comment below for posterity:
     *
     * The frequency thing is a bit more interesting, but still not too complex.
     * Each three letters are base-95 encoded number representing the chance that
     * this combination comes next.  Subtract the value of ' ' from each of the
     * three, then ((((first_value * 95) + second_value) * 95) + third_value) will
     * give you the odds that this pair is grouped together.  The first is "  "
     * (non-alpha chars), then " a", " b", etc. " y", " z", "a ", "aa", "ab", and
     * so on.  If you decrypt the table successfully, you should see a really large
     * number for "qu".
     * @return array
     */
    private function getFrequencyTable(){
        return array('0.23653710453418866','0.04577693541332556','0.03449832337075375','0.042918209651552706','0.037390873305146524','0.028509112115468728','0.02350896632162123','0.022188657238664526','0.028429800262428927','0.04357019973757107','0.00913602565971716','0.03223093745443942','0.02235311269864412','0.04438081352966905','0.04512377897652719','0.020055401662049863','0.055903192885260244','0.0024388394809739026','0.035207464644991984','0.07355941099285611','0.036905671380667734','0.026134421927394666','0.023787724158040528','0.011352092141711621','0.0032354570637119114','0.005986878553725033','0.008861933226417843','0.11511532293337222','0.027556203528211108','0.024331243621519172','0.039266365359381834','0.031599941682461','0.014403265782183991','0.015480973902901297','0.027770812071730572','0.00942761335471643','0.039872867764980315','0.0078122175244204695','0.02808456043154979','0.08429100451960927','0.04688963405744277','0.13831170724595424','0.002540311998833649','0.025211838460416972','0.001543082081936142','0.09519638431258201','0.061845750109345385','0.08907071001603732','0.02137571074500656','0.027093162268552268','0.005521504592506197','0.003023181221752442','0.007086747339262283','0.010262720513194342','0.08785070710016038','0.14617757690625455','0.03417291150313457','0.0059635515381250915','0.006146668610584633','0.195202799241872','0.002774748505613063','0.004715556203528212','0.0044776206444088066','0.11205481848665985','0.005654468581425864','0.0028820527773727946','0.07383000437381543','0.005516839189386207','0.006496573844583759','0.09843067502551392','0.0027140982650532145','0.0006893133109782768','0.08425368129464937','0.021325557661466685','0.006493074792243767','0.07023414491908442','0.002077270739174807','0.0024633328473538415','0.0007744569179180639','0.015413325557661468','0.0011990086018370024','0.13162851727657093','0.10115993585070711','0.0026989357049132527','0.03319317684793702','0.002946202070272634','0.0783216212275842','0.0018358361277154103','0.00258813238081353','0.2141688292754046','0.09853681294649366','0.0032482869222918796','0.04359352675317102','0.01993526753171016','0.0036880011663507797','0.008011663507799971','0.12014696019827964','0.0029846916460125384','0.0017553579238956116','0.029470185158186325','0.010413179763813967','0.030699518880303252','0.03508499781309229','0.002021285901734947','0.0010613792097973467','0.0005295232541186761','0.009677212421635807','0.010585799679253535','0.17101734946785244','0.07968625164018078','0.007839043592360402','0.005438693687126403','0.0183606939787141','0.2732701559994168','0.004953491762647616','0.007259367254701851','0.008104971570199739','0.13274588132380813','0.004210526315789474','0.004997813092287506','0.017006560723137484','0.007442484327161393','0.016789619478058026','0.08477737279486806','0.005106283714827234','0.0005026971861787433','0.04040355736987899','0.037535500801866156','0.00885960052485785','0.0336410555474559','0.007066919376002332','0.005344219273946639','0.0006333284735384167','0.010684939495553289','0.0063064586674442345','0.15386849394955532','0.015049424114302375','0.012162705933809595','0.020425134859308938','0.037366379938766583','0.02157165767604607','0.009373961218836564','0.0173214754337367','0.009616562181075958','0.029522670943286193','0.010154249890654615','0.018600962239393497','0.06362210234728094','0.03157078291296107','0.151603440734801','0.0062329785683044175','0.014775331681003062','0.0020854351946347867','0.1826342032366234','0.0878017203674005','0.054190989940224525','0.010329202507654177','0.012763376585508092','0.0064872430383437815','0.006381105117364048','0.005388540603586529','0.0090800408222773','0.09611196967487973','0.09940691062837148','0.01033969966467415','0.004034407348009914','0.008826942703017933','0.11474675608689314','0.07132584924916169','0.012388977985129028','0.005435194634786413','0.1417174515235457','0.0037066627788307337','0.0045802595130485495','0.060800699810468','0.005341886572386646','0.005683627350925791','0.12434932205860913','0.004596588423968508','0.0007534626038781163','0.07107041842834232','0.022361277154104096','0.04784720804782038','0.06277533168100306','0.003441901151771395','0.005828254847645429','0.0009669047966175828','0.009470768333576322','0.002077270739174807','0.12797667298440007','0.08797783933518005','0.005388540603586529','0.0024913252660737715','0.007550954949701123','0.2786866890217233','0.002509986878553725','0.029002478495407494','0.0303204548768042','0.07576614666861058','0.00246799825047383','0.00592389561160519','0.039574281965301064','0.00706808572678233','0.03304505029887739','0.05474150750838315','0.0028633911648928414','0.0005073625892987316','0.07293541332555767','0.053528502697186175','0.022566554891383584','0.038151334013704616','0.002716430966613209','0.005049132526607377','0.0009902318122175246','0.008997229916897508','0.0011861787432570347','0.1666377022889634','0.14414462749671964','0.003374252806531564','0.005169266656947077','0.008468873013558828','0.16337541915731155','0.002873888321912815','0.004305000728969237','0.0031141565825922144','0.1241172182533897','0.0052800699810468','0.008969237498177577','0.024094474413179766','0.017029887738737422','0.01722700102055693','0.10618457501093455','0.006147834961364631','0.0008269427030179326','0.03303571949263741','0.024188948826359528','0.05213937891820965','0.04505846333284735','0.0035270447587111824','0.006799825047383001','0.0008199445983379502','0.02206735675754483','0.001010059775477475','0.11971191135734072','0.04656538854060359','0.011243621519171892','0.06513019390581717','0.032375564951159064','0.06347047674588133','0.013678961947805804','0.03309870243475726','0.006982942119842543','0.009726199154395685','0.010121592068814697','0.032514360693978714','0.04986032949409535','0.039734072022160664','0.15690683773144773','0.03949963551538125','0.014790494241143023','0.002722262720513194','0.02614375273363464','0.10753637556495116','0.06764834523983088','0.006221315060504448','0.021317393206006705','0.0030826651115322934','0.002399183554454002','0.0019069835252952323','0.015595276279341012','0.0925126111678087','0.18437906400349907','0.006538562472663654','0.008719638431258201','0.02116693395538708','0.18241376293920394','0.007290858725761773','0.005976381396705059','0.005629975215045925','0.09721300481119698','0.004810030616707975','0.024303251202799244','0.012954658113427612','0.011057005394372358','0.02733459688001166','0.10135121737862662','0.012016912086309959','0.001055547455897361','0.009027555037177431','0.07162326869806095','0.01007143898527482','0.07297623560285756','0.006741507508383147','0.0036891675171307776','0.0008409389123778977','0.011272780288671819','0.007020265344802449','0.1030389269572824','0.15350809155853623','0.004232686980609419','0.004353987461729115','0.0023385333138941536','0.14450386353695874','0.002546143752733635','0.0024470039364338824','0.01200758128006998','0.0981227584195947','0.003161976964572095','0.040695145064878264','0.03460446129173349','0.003908441463770229','0.01598483743986004','0.13107216795451232','0.003129319142732177','0.00032307916605919226','0.04050386353695874','0.05452689896486368','0.03589677795597026','0.07087097244496282','0.006143169558244642','0.008684647907858289','0.0004607085580988482','0.022010205569324977','0.0009097536083977258','0.07328765126111678','0.14751421490013122','0.008015162560139961','0.006601545414783497','0.025279486805656802','0.1682449336637994','0.008313748359819215','0.007010934538562473','0.005886572386645284','0.16889575739903775','0.004123050007289692','0.011925936725470185','0.10007289692374982','0.013380376148126549','0.009021723283277445','0.08650823735238372','0.007756232686980609','0.0007243038343781893','0.0026791077416533026','0.02797492345823006','0.032384895757399036','0.04187432570345531','0.00882461000145794','0.0032401224668318998','0.00033357632307916605','0.027878116343490307','0.0022277299897944304','0.14333518005540166','0.1725534334451086','0.02781629975215046','0.006909462020702727','0.005264907420906838','0.16661437527336345','0.004325995043009185','0.003334596880011664','0.005312727802886718','0.14024668318996938','0.0013261408368566844','0.003504884093891238','0.006375273363464061','0.04964922000291588','0.008290421344219274','0.09536783787724158','0.05394372357486515','0.005505175681586237','0.005339553870826651','0.01782067356757545','0.006710016037323225','0.05105933809593235','0.002983525295232541','0.002940370316372649','0.0004548768041988629','0.01208456043154979','0.000915585362297711','0.20146260387811635','0.067196967487972','0.006158332118384605','0.025438110511736407','0.07753783350342616','0.1273876658405015','0.009337804344656656','0.07683452398308792','0.0070412596588423975','0.08747164309666132','0.0038827817466102928','0.018116926665694706','0.005017641055547455','0.004567429654468581','0.028277008310249308','0.05271555620352821','0.004394809739029013','0.0013343052923166642','0.00411605190260971','0.059621519171890944','0.09073859163143316','0.01446858142586383','0.006770666277883074','0.003425572240851436','0.0004455459979588861','0.010401516256013998','0.005825922146085436','0.10833882490158916','0.007584779122321038','0.016903921854497742','0.02719580113719201','0.0304814112844438','0.02206385770520484','0.013064295086747339','0.02696369733197259','0.009581571657676046','0.026761918647033093','0.006510570053943724','0.021941390873305145','0.07042659279778393','0.05437410701268406','0.1425175681586237','0.027802303542790494','0.037690625455605774','0.0019606356611750987','0.1095623268698061','0.06157748942994606','0.044618749088788455','0.04955124653739612','0.03608689313310978','0.018381688292754043','0.003404577926811489','0.015036594255722409','0.009600233270156','0.10794693103951014','0.12447528794284882','0.0031981338387520046','0.0074716430966613205','0.003202799241871993','0.13437643971424407','0.006655197550663361','0.0036693395538708266','0.049338970695436656','0.09486863974340283','0.0015990669193760023','0.0026604461291733486','0.051775477474850555','0.0041347135150896636','0.005450357194926374','0.12030325120279925','0.04581309228750547','0.0004537104534188657','0.12425601399620935','0.025981629975215047','0.023926519900860182','0.04423385333138941','0.0017950138504155123','0.002661612479953346','0.0006333284735384167','0.008449045050298877','0.000653156436798367','0.04816678816153958','0.008625164018078437','0.0039037760606502403','0.005228750546726928','0.004531272780288672','0.0056672984400058316','0.00359585945473101','0.0032179618020119548','0.0038093016474704767','0.011452398308791368','0.002519317684793702','0.00280390727511299','0.005572824026826068','0.004554599795888614','0.004531272780288672','0.0035841959469310393','0.004400641492928998','0.0036670068523108326','0.004839189386207902','0.006258638285464354','0.004897506925207757','0.840776789619478','0.004968654322787578','0.002886718180492783','0.0019757982213150604','0.0018568304417553576','0.001691208630995772','0.09009243329931477','0.14030150167662925','0.013242746756086894','0.013746610293045632','0.027342761335471644','0.16938912377897652','0.006607377168683481','0.01661933226417845','0.008173786266219566','0.13297448607668758','0.0034675608689313307','0.016641492928998396','0.011722991689750693','0.021493512173786266','0.03430820819361423','0.10099548039072752','0.00873596734217816','0.0018323370753754193','0.020103222044029742','0.047197550663362','0.040833940807697915','0.03361189677795597','0.010844729552412887','0.005544831608106138','0.0007522962530981193','0.01525120279924187','0.00815512465373961','0.2109648636827526','0.058258055110074355','0.007181221752442048','0.043560868931331105','0.004058900714389853','0.10618107595859454','0.0062399766729844','0.004835690333867911','0.02679224376731302','0.08414637702288964','0.0030698352529523252','0.03637498177576906','0.01592885260242018','0.017413617145356466','0.008430383437818923','0.037231083248286924','0.03290275550371775','0.007538125091121154','0.004500947660008748','0.05932409972299169','0.16006764834523984','0.03309636973319726','0.007766729844000583','0.005225251494386936','0.0006321621227584196','0.012989648636827526','0.005274238227146815','0.1254503571949264','0.12852719055255868','0.0035433736696311416','0.005203090829566993','0.0019314768916751715','0.20520775623268697','0.002509986878553725','0.00343606939787141','0.027138649948972155','0.13926578218399185','0.004565096952908587','0.005614812654905963','0.00874413179763814','0.004109053797929727','0.008300918501239247','0.08270943286193323','0.002912377897652719','0.0037066627788307337','0.06909578655780726','0.03242805073625893','0.05237614812654906','0.04723487388832191','0.0038991106575302524','0.006299460562764251','0.00043388249015891526','0.020029741944889927','0.005311561452106721','0.09334072022160665','0.022940953491762648','0.024658988190698353','0.02901297565242747','0.03531593526753171','0.0758023035427905','0.013711619769645722','0.021597317393206007','0.009670214316955824','0.044728386062108175','0.010596296836273509','0.03264382563055839','0.0604822860475288','0.05489546581134276','0.11501851581863246','0.01837585653885406','0.026237060796034405','0.0011255285026971862','0.08704125965884241','0.10156349322058608','0.06660562764251349','0.023434319871701415','0.010777081207173057','0.005409534917626476','0.003123487388832191','0.0028762210234728096','0.0089995626184575','0.07518297127861205','0.2314868056568013','0.002226563639014434','0.003285610147251786','0.0027455897361131363','0.2724537104534189','0.0016655489138358362','0.0019209797346551977','0.0022137337804344656','0.17690392185449774','0.0014532730718763668','0.0024994897215337513','0.015302522233561744','0.003441901151771395','0.015303688584341741','0.09314593964134713','0.0017833503426155418','0.0005108616416387229','0.017828838023035427','0.010385187345094037','0.003168975069252078','0.01902901297565243','0.005525003644846187','0.0010088934246974776','0.0009272488700976819','0.036282840064149294','0.0022977110365942554','0.0766805656801283','0.22270418428342326','0.005283569033386791','0.007155562035282111','0.01173582154833066','0.1715620352821111','0.003925936725470185','0.004425134859308937','0.020040239101909902','0.14243242455168392','0.0016737133692958156','0.0066808572678232975','0.011980755212130047','0.012638577052048404','0.07206065024055984','0.08115701997375711','0.00710424260096224','0.0007278028867181805','0.02347630849978131','0.04595538708266512','0.01481965301064295','0.013925061962385188','0.0018125091121154687','0.00529173348884677','0.0016340574427759146','0.03072401224668319','0.0023746901880740633','0.25174165330223064','0.06673392622831317','0.00878378772415804','0.03956261845750109','0.010077270739174807','0.0844787869951888','0.00985216503863537','0.004973319725907567','0.01893220586091267','0.11200583175389998','0.0028715556203528212','0.004095057588569762','0.01202391019098994','0.01756757544831608','0.014825484764542934','0.05312961073042717','0.06746872721971132','0.003845458521650386','0.0210806239976673','0.019443067502551394','0.08017028721387957','0.01825572240851436','0.005365213587986587','0.01959702580551101','0.026184575010934536','0.02474879720075813','0.002171745152354571','0.25827321767021433','0.048050153083539875','0.01043184137629392','0.03930485493512174','0.027640180784370902','0.03294007872867765','0.006474413179763814','0.018314039947514214','0.015119405161102202','0.014706516984983233','0.005494678524566263','0.03309870243475726','0.043864120134130345','0.058996355153812505','0.06265986295378335','0.04633328473538417','0.03790756670068523','0.0004642076104388394','0.037849249161685375','0.08369966467415076','0.04999679253535501','0.02392768625164018','0.010998687855372504','0.009881323808135296','0.003867619186470331','0.012434465665548913','0.007253535500801866','0.11106225397288234','0.17624726636535937','0.008209943140399476','0.008390727511299025','0.012682898381688294','0.1825653885406036','0.001538416678816154','0.004590756670068524','0.008710307625018223','0.1299513048549351','0.002677941390873305','0.012309666132089225','0.014087184720804781','0.01199941682461','0.031246537396121883','0.07206648199445984','0.008254264470039366','0.0007033095203382417','0.007034261554162415','0.006599212713223502','0.013906400349905234','0.050098265053214755','0.007133401370462167','0.017750692520775622','0.0008257763522379356','0.03918821985712203','0.06015454147834961');
    }

	/**
	 * Helper method to return hard coded $entropyAry array
     * This data is based on the assumption of 350 billion guesses per second.
     * The lowest amount of days used is set at the top of this class so you can easily
     * change this to something else if you'd like.
	 * @return array $entropyAry
	 */
    private function getEntropyArray(){
        $entropyAry = array();
        $i = 1; // 1 based is correct, no zero based!
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '3 picoseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '6 picoseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '12 picoseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '24 picoseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '48 picoseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '96 picoseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '172 picoseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '384 picoseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '768 picoseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '1.5 nanoseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '3 nanoseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '6 nanoseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '12 nanoseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '24 nanoseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '48 nanoseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '96 nanoseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '172 nanoseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '384 nanoseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '748 nanoseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '1.5 microseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '3 microseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '6 microseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '12 microseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '24 microseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '48 microseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '95 microseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '192 microseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '383 microseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '763 microseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '1.5 milliseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '3 milliseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '6 milliseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '12 milliseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '24 milliesconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '49 milliseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '98 milliseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '196 milliseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '393 milliseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => $this->min_days_valid, 'time_to_crack' => '785 milliseconds', 'valid' => $this->min_days_labels);
		$entropyAry[$i++] = array('days' => 0.00001817130, 'time_to_crack' => '1.57 seconds', 'valid' => '1.57 seconds');
		$entropyAry[$i++] = array('days' => 0.00003634259, 'time_to_crack' => '3.14 seconds', 'valid' => '3.14 seconds');
		$entropyAry[$i++] = array('days' => 0.00007268519, 'time_to_crack' => '6.28 seconds', 'valid' => '6.28 seconds');
		$entropyAry[$i++] = array('days' => 0.00014583333, 'time_to_crack' => '12.6 seconds', 'valid' => '12.6 seconds');
		$entropyAry[$i++] = array('days' => 0.00028935185, 'time_to_crack' => '25 seconds', 'valid' => '25 seconds');
		$entropyAry[$i++] = array('days' => 0.00057870370, 'time_to_crack' => '50 seconds', 'valid' => '50 seconds');
		$entropyAry[$i++] = array('days' => 0.00138888889, 'time_to_crack' => '2 minutes', 'valid' => '2 minutes');
		$entropyAry[$i++] = array('days' => 0.00208333333, 'time_to_crack' => '3 minutes', 'valid' => '3 minutes');
		$entropyAry[$i++] = array('days' => 0.00486111111, 'time_to_crack' => '7 minutes', 'valid' => '7 minutes');
		$entropyAry[$i++] = array('days' => 0.00902777778, 'time_to_crack' => '13 minutes', 'valid' => '13 minutes');
		$entropyAry[$i++] = array('days' => 0.01875000000, 'time_to_crack' => '27 minutes', 'valid' => '27 minutes');
		$entropyAry[$i++] = array('days' => 0.03750000000, 'time_to_crack' => '54 minutes', 'valid' => '54 minutes');
		$entropyAry[$i++] = array('days' => 0.08333333333, 'time_to_crack' => '2 hours', 'valid' => '2 hours');
		$entropyAry[$i++] = array('days' => 0.16666666667, 'time_to_crack' => '4 hours', 'valid' => '4 hours');
		$entropyAry[$i++] = array('days' => 0.29166666667, 'time_to_crack' => '7 hours', 'valid' => '7 hours');
		$entropyAry[$i++] = array('days' => 0.58333333333, 'time_to_crack' => '14 hours', 'valid' => '14 hours');
		$entropyAry[$i++] = array('days' => 1, 'time_to_crack' => '1 day', 'valid' => '1 day');
		$entropyAry[$i++] = array('days' => 2, 'time_to_crack' => '2 days', 'valid' => '2 days');
		$entropyAry[$i++] = array('days' => 5, 'time_to_crack' => '5 days', 'valid' => '5 days');
		$entropyAry[$i++] = array('days' => 7, 'time_to_crack' => '1 week', 'valid' => '1 week');
		$entropyAry[$i++] = array('days' => 21, 'time_to_crack' => '3 weeks', 'valid' => '3 weeks');
        $entropyAry[$i++] = array('days' => '37', 'time_to_crack' => '1 month', 'valid' => '1 month');
        $entropyAry[$i++] = array('days' => '74', 'time_to_crack' => '3 months', 'valid' => '3 months');
        $entropyAry[$i++] = array('days' => '142', 'time_to_crack' => '5 months', 'valid' => '5 months');
        $entropyAry[$i++] = array('days' => '268', 'time_to_crack' => '1 year', 'valid' => '1 year');
        $entropyAry[$i++] = array('days' => '481', 'time_to_crack' => '1 year', 'valid' => '1 year');
        $entropyAry[$i++] = array('days' => '810', 'time_to_crack' => '2 years', 'valid' => '2 years');
        $entropyAry[$i++] = array('days' => '1263', 'time_to_crack' => '3 years', 'valid' => '3 years');
        $entropyAry[$i++] = array('days' => '1821', 'time_to_crack' => '5 years', 'valid' => '5 years');
        $entropyAry[$i++] = array('days' => '2454', 'time_to_crack' => '7 years', 'valid' => '7 years');
        $entropyAry[$i++] = array('days' => '3132', 'time_to_crack' => '9 years', 'valid' => '9 years');
        $entropyAry[$i++] = array('days' => '3835', 'time_to_crack' => '10 years', 'valid' => '10 years');
        $entropyAry[$i++] = array('days' => '4551', 'time_to_crack' => '12 years', 'valid' => '12 years');
        $entropyAry[$i++] = array('days' => '5275', 'time_to_crack' => '14 years', 'valid' => '14 years');
        $entropyAry[$i++] = array('days' => '6002', 'time_to_crack' => '16 years', 'valid' => '16 years');
        $entropyAry[$i++] = array('days' => '6731', 'time_to_crack' => '18 years', 'valid' => '18 years');
        $entropyAry[$i++] = array('days' => '7460', 'time_to_crack' => '20 years', 'valid' => '20 years');
        $entropyAry[$i++] = array('days' => '8190', 'time_to_crack' => '22 years', 'valid' => '22 years');
        $entropyAry[$i++] = array('days' => '8920', 'time_to_crack' => '24 years', 'valid' => '24 years');
        $entropyAry[$i++] = array('days' => '9651', 'time_to_crack' => '26 years', 'valid' => '26 years');
        $entropyAry[$i++] = array('days' => '10381', 'time_to_crack' => '28 years', 'valid' => '28 years');
        $entropyAry[$i++] = array('days' => '11112', 'time_to_crack' => '30 years', 'valid' => '30 years');
        $entropyAry[$i++] = array('days' => '11842', 'time_to_crack' => '32 years', 'valid' => '32 years');
        $entropyAry[$i++] = array('days' => '12573', 'time_to_crack' => '34 years', 'valid' => '34 years');
        $entropyAry[$i++] = array('days' => '13303', 'time_to_crack' => '36 years', 'valid' => '36 years');
        $entropyAry[$i++] = array('days' => '14034', 'time_to_crack' => '38 years', 'valid' => '38 years');
        $entropyAry[$i++] = array('days' => '14764', 'time_to_crack' => '40 years', 'valid' => '40 years');
        $entropyAry[$i++] = array('days' => '15495', 'time_to_crack' => '42 years', 'valid' => '42 years');
        $entropyAry[$i++] = array('days' => '16225', 'time_to_crack' => '44 years', 'valid' => '44 years');
        $entropyAry[$i++] = array('days' => '16956', 'time_to_crack' => '46 years', 'valid' => '46 years');
        $entropyAry[$i++] = array('days' => '17686', 'time_to_crack' => '48 years', 'valid' => '48 years');
        $entropyAry[$i++] = array('days' => '18417', 'time_to_crack' => '50 years', 'valid' => '50 years');
        $entropyAry[$i++] = array('days' => '19147', 'time_to_crack' => '52 years', 'valid' => '52 years');
        $entropyAry[$i++] = array('days' => '19878', 'time_to_crack' => '54 years', 'valid' => '54 years');
        $entropyAry[$i++] = array('days' => '20608', 'time_to_crack' => '56 years', 'valid' => '56 years');
        $entropyAry[$i++] = array('days' => '21339', 'time_to_crack' => '58 years', 'valid' => '58 years');
        $entropyAry[$i++] = array('days' => '22069', 'time_to_crack' => '60 years', 'valid' => '60 years');
        $entropyAry[$i++] = array('days' => '22800', 'time_to_crack' => '62 years', 'valid' => '62 years');
        $entropyAry[$i++] = array('days' => '23530', 'time_to_crack' => '64 years', 'valid' => '64 years');
        $entropyAry[$i++] = array('days' => '24261', 'time_to_crack' => '66 years', 'valid' => '66 years');
        $entropyAry[$i++] = array('days' => '24991', 'time_to_crack' => '68 years', 'valid' => '68 years');
        $entropyAry[$i++] = array('days' => '25722', 'time_to_crack' => '70 years', 'valid' => '70 years');
        $entropyAry[$i++] = array('days' => '26452', 'time_to_crack' => '72 years', 'valid' => '72 years');
        $entropyAry[$i++] = array('days' => '27183', 'time_to_crack' => '74 years', 'valid' => '74 years');
        $entropyAry[$i++] = array('days' => '27913', 'time_to_crack' => '76 years', 'valid' => '76 years');
        $entropyAry[$i++] = array('days' => '28644', 'time_to_crack' => '78 years', 'valid' => '78 years');
        $entropyAry[$i++] = array('days' => '29374', 'time_to_crack' => '80 years', 'valid' => '80 years');
        $entropyAry[$i++] = array('days' => '30105', 'time_to_crack' => '82 years', 'valid' => '82 years');
        $entropyAry[$i++] = array('days' => '30835', 'time_to_crack' => '84 years', 'valid' => '84 years');
        $entropyAry[$i++] = array('days' => '31566', 'time_to_crack' => '86 years', 'valid' => '86 years');
        $entropyAry[$i++] = array('days' => '32296', 'time_to_crack' => '88 years', 'valid' => '88 years');
        $entropyAry[$i++] = array('days' => '33027', 'time_to_crack' => '90 years', 'valid' => '90 years');
        $entropyAry[$i++] = array('days' => '33757', 'time_to_crack' => '92 years', 'valid' => '92 years');
        $entropyAry[$i++] = array('days' => '34488', 'time_to_crack' => '94 years', 'valid' => '94 years');
        $entropyAry[$i++] = array('days' => '35218', 'time_to_crack' => '96 years', 'valid' => '96 years');
        $entropyAry[$i++] = array('days' => '35949', 'time_to_crack' => '98 years', 'valid' => '98 years');
        $entropyAry[$i++] = array('days' => '36679', 'time_to_crack' => '100 years', 'valid' => '100 years');
        $entropyAry[$i++] = array('days' => '37410', 'time_to_crack' => '102 years', 'valid' => '102 years');
        $entropyAry[$i++] = array('days' => '38140', 'time_to_crack' => '104 years', 'valid' => '104 years');
        $entropyAry[$i++] = array('days' => '38871', 'time_to_crack' => '106 years', 'valid' => '106 years');
        $entropyAry[$i++] = array('days' => '39601', 'time_to_crack' => '108 years', 'valid' => '108 years');
        $entropyAry[$i++] = array('days' => '40332', 'time_to_crack' => '110 years', 'valid' => '110 years');
        $entropyAry[$i++] = array('days' => '41062', 'time_to_crack' => '112 years', 'valid' => '112 years');
        $entropyAry[$i++] = array('days' => '41793', 'time_to_crack' => '114 years', 'valid' => '114 years');
        $entropyAry[$i++] = array('days' => '42523', 'time_to_crack' => '116 years', 'valid' => '116 years');
        $entropyAry[$i++] = array('days' => '43254', 'time_to_crack' => '118 years', 'valid' => '118 years');
        $entropyAry[$i++] = array('days' => '43984', 'time_to_crack' => '120 years', 'valid' => '120 years');
        $entropyAry[$i++] = array('days' => '44715', 'time_to_crack' => '122 years', 'valid' => '122 years');
        $entropyAry[$i++] = array('days' => '45445', 'time_to_crack' => '124 years', 'valid' => '124 years');
        $entropyAry[$i++] = array('days' => '46176', 'time_to_crack' => '126 years', 'valid' => '126 years');
        $entropyAry[$i++] = array('days' => '46906', 'time_to_crack' => '128 years', 'valid' => '128 years');
        $entropyAry[$i++] = array('days' => '47637', 'time_to_crack' => '130 years', 'valid' => '130 years');
        $entropyAry[$i++] = array('days' => '48367', 'time_to_crack' => '132 years', 'valid' => '132 years');
        $entropyAry[$i++] = array('days' => '49098', 'time_to_crack' => '134 years', 'valid' => '134 years');
        $entropyAry[$i++] = array('days' => '49828', 'time_to_crack' => '136 years', 'valid' => '136 years');
        $entropyAry[$i++] = array('days' => '50559', 'time_to_crack' => '138 years', 'valid' => '138 years');
        $entropyAry[$i++] = array('days' => '51289', 'time_to_crack' => '140 years', 'valid' => '140 years');
        $entropyAry[$i++] = array('days' => '52020', 'time_to_crack' => '142 years', 'valid' => '142 years');
        $entropyAry[$i++] = array('days' => '52750', 'time_to_crack' => '144 years', 'valid' => '144 years');
        $entropyAry[$i++] = array('days' => '53481', 'time_to_crack' => '146 years', 'valid' => '146 years');
        $entropyAry[$i++] = array('days' => '54211', 'time_to_crack' => '148 years', 'valid' => '148 years');
        $entropyAry[$i++] = array('days' => '54942', 'time_to_crack' => '150 years', 'valid' => '150 years');
        $entropyAry[$i++] = array('days' => '55672', 'time_to_crack' => '152 years', 'valid' => '152 years');
        $entropyAry[$i++] = array('days' => '56403', 'time_to_crack' => '154 years', 'valid' => '154 years');
        $entropyAry[$i++] = array('days' => '57133', 'time_to_crack' => '156 years', 'valid' => '156 years');
        $entropyAry[$i++] = array('days' => '57864', 'time_to_crack' => '158 years', 'valid' => '158 years');
        $entropyAry[$i++] = array('days' => '58594', 'time_to_crack' => '160 years', 'valid' => '160 years');
        $entropyAry[$i++] = array('days' => '59325', 'time_to_crack' => '162 years', 'valid' => '162 years');
        $entropyAry[$i++] = array('days' => '60055', 'time_to_crack' => '164 years', 'valid' => '164 years');
        $entropyAry[$i++] = array('days' => '60786', 'time_to_crack' => '166 years', 'valid' => '166 years');
        $entropyAry[$i++] = array('days' => '61516', 'time_to_crack' => '168 years', 'valid' => '168 years');
        $entropyAry[$i++] = array('days' => '62247', 'time_to_crack' => '170 years', 'valid' => '170 years');
        $entropyAry[$i++] = array('days' => '62977', 'time_to_crack' => '172 years', 'valid' => '172 years');
        $entropyAry[$i++] = array('days' => '63708', 'time_to_crack' => '174 years', 'valid' => '174 years');
        $entropyAry[$i++] = array('days' => '64438', 'time_to_crack' => '176 years', 'valid' => '176 years');
        $entropyAry[$i++] = array('days' => '65169', 'time_to_crack' => '178 years', 'valid' => '178 years');
        $entropyAry[$i++] = array('days' => '65899', 'time_to_crack' => '180 years', 'valid' => '180 years');
        $entropyAry[$i++] = array('days' => '66630', 'time_to_crack' => '182 years', 'valid' => '182 years');
        $entropyAry[$i++] = array('days' => '67360', 'time_to_crack' => '184 years', 'valid' => '184 years');
        $entropyAry[$i++] = array('days' => '68091', 'time_to_crack' => '186 years', 'valid' => '186 years');
        $entropyAry[$i++] = array('days' => '68821', 'time_to_crack' => '188 years', 'valid' => '188 years');
        $entropyAry[$i++] = array('days' => '69552', 'time_to_crack' => '190 years', 'valid' => '190 years');
        $entropyAry[$i++] = array('days' => '70282', 'time_to_crack' => '192 years', 'valid' => '192 years');
        $entropyAry[$i++] = array('days' => '71013', 'time_to_crack' => '194 years', 'valid' => '194 years');
        $entropyAry[$i++] = array('days' => '71743', 'time_to_crack' => '196 years', 'valid' => '196 years');
        $entropyAry[$i++] = array('days' => '72474', 'time_to_crack' => '198 years', 'valid' => '198 years');
        $entropyAry[$i++] = array('days' => '73204', 'time_to_crack' => '200 years', 'valid' => '200 years');
        $entropyAry[$i++] = array('days' => '73935', 'time_to_crack' => '202 years', 'valid' => '202 years');
        $entropyAry[$i++] = array('days' => '74665', 'time_to_crack' => '204 years', 'valid' => '204 years');
        $entropyAry[$i++] = array('days' => '75396', 'time_to_crack' => '206 years', 'valid' => '206 years');
        $entropyAry[$i++] = array('days' => '76126', 'time_to_crack' => '208 years', 'valid' => '208 years');
        $entropyAry[$i++] = array('days' => '76857', 'time_to_crack' => '210 years', 'valid' => '210 years');
        $entropyAry[$i++] = array('days' => '77587', 'time_to_crack' => '212 years', 'valid' => '212 years');
        $entropyAry[$i++] = array('days' => '78318', 'time_to_crack' => '214 years', 'valid' => '214 years');
        $entropyAry[$i++] = array('days' => '79048', 'time_to_crack' => '216 years', 'valid' => '216 years');
        $entropyAry[$i++] = array('days' => '79779', 'time_to_crack' => '218 years', 'valid' => '218 years');
        $entropyAry[$i++] = array('days' => '80509', 'time_to_crack' => '220 years', 'valid' => '220 years');
        $entropyAry[$i++] = array('days' => '81240', 'time_to_crack' => '222 years', 'valid' => '222 years');
        $entropyAry[$i++] = array('days' => '81970', 'time_to_crack' => '224 years', 'valid' => '224 years');
        $entropyAry[$i++] = array('days' => '82701', 'time_to_crack' => '226 years', 'valid' => '226 years');
        $entropyAry[$i++] = array('days' => '83431', 'time_to_crack' => '228 years', 'valid' => '228 years');
        $entropyAry[$i++] = array('days' => '84162', 'time_to_crack' => '230 years', 'valid' => '230 years');
        $entropyAry[$i++] = array('days' => '84892', 'time_to_crack' => '232 years', 'valid' => '232 years');
        $entropyAry[$i++] = array('days' => '85623', 'time_to_crack' => '234 years', 'valid' => '234 years');
        $entropyAry[$i++] = array('days' => '86353', 'time_to_crack' => '236 years', 'valid' => '236 years');
        $entropyAry[$i++] = array('days' => '87084', 'time_to_crack' => '238 years', 'valid' => '238 years');
        $entropyAry[$i++] = array('days' => '87814', 'time_to_crack' => '240 years', 'valid' => '240 years');
        $entropyAry[$i++] = array('days' => '88545', 'time_to_crack' => '242 years', 'valid' => '242 years');
        $entropyAry[$i++] = array('days' => '89275', 'time_to_crack' => '244 years', 'valid' => '244 years');
        $entropyAry[$i++] = array('days' => '90006', 'time_to_crack' => '246 years', 'valid' => '246 years');
        $entropyAry[$i++] = array('days' => '90736', 'time_to_crack' => '248 years', 'valid' => '248 years');
        $entropyAry[$i++] = array('days' => '91467', 'time_to_crack' => '250 years', 'valid' => '250 years');
        $entropyAry[$i++] = array('days' => '92197', 'time_to_crack' => '252 years', 'valid' => '252 years');
        $entropyAry[$i++] = array('days' => '92928', 'time_to_crack' => '254 years', 'valid' => '254 years');
        $entropyAry[$i++] = array('days' => '93658', 'time_to_crack' => '256 years', 'valid' => '256 years');
        $entropyAry[$i++] = array('days' => '94389', 'time_to_crack' => '258 years', 'valid' => '258 years');
        $entropyAry[$i++] = array('days' => '95119', 'time_to_crack' => '260 years', 'valid' => '260 years');
        $entropyAry[$i++] = array('days' => '95850', 'time_to_crack' => '262 years', 'valid' => '262 years');
        $entropyAry[$i++] = array('days' => '96580', 'time_to_crack' => '264 years', 'valid' => '264 years');
        $entropyAry[$i++] = array('days' => '97311', 'time_to_crack' => '266 years', 'valid' => '266 years');
        $entropyAry[$i++] = array('days' => '98041', 'time_to_crack' => '268 years', 'valid' => '268 years');
        $entropyAry[$i++] = array('days' => '98772', 'time_to_crack' => '270 years', 'valid' => '270 years');
        $entropyAry[$i++] = array('days' => '99502', 'time_to_crack' => '272 years', 'valid' => '272 years');
        $entropyAry[$i++] = array('days' => '100233', 'time_to_crack' => '274 years', 'valid' => '274 years');
        $entropyAry[$i++] = array('days' => '100963', 'time_to_crack' => '276 years', 'valid' => '276 years');
        $entropyAry[$i++] = array('days' => '101694', 'time_to_crack' => '278 years', 'valid' => '278 years');
        $entropyAry[$i++] = array('days' => '102424', 'time_to_crack' => '280 years', 'valid' => '280 years');
        $entropyAry[$i++] = array('days' => '103155', 'time_to_crack' => '282 years', 'valid' => '282 years');
        $entropyAry[$i++] = array('days' => '103885', 'time_to_crack' => '284 years', 'valid' => '284 years');
        $entropyAry[$i++] = array('days' => '104616', 'time_to_crack' => '286 years', 'valid' => '286 years');
        $entropyAry[$i++] = array('days' => '105346', 'time_to_crack' => '288 years', 'valid' => '288 years');
        $entropyAry[$i++] = array('days' => '106077', 'time_to_crack' => '290 years', 'valid' => '290 years');
        $entropyAry[$i++] = array('days' => '106807', 'time_to_crack' => '292 years', 'valid' => '292 years');
        $entropyAry[$i++] = array('days' => '107538', 'time_to_crack' => '294 years', 'valid' => '294 years');
        $entropyAry[$i++] = array('days' => '108268', 'time_to_crack' => '296 years', 'valid' => '296 years');
        $entropyAry[$i++] = array('days' => '108999', 'time_to_crack' => '298 years', 'valid' => '298 years');
        $entropyAry[$i++] = array('days' => '109729', 'time_to_crack' => '300 years', 'valid' => '300 years');
        $entropyAry[$i++] = array('days' => '110460', 'time_to_crack' => '302 years', 'valid' => '302 years');
        $entropyAry[$i++] = array('days' => '111190', 'time_to_crack' => '304 years', 'valid' => '304 years');
        $entropyAry[$i++] = array('days' => '111921', 'time_to_crack' => '306 years', 'valid' => '306 years');
        $entropyAry[$i++] = array('days' => '112651', 'time_to_crack' => '308 years', 'valid' => '308 years');
        $entropyAry[$i++] = array('days' => '113382', 'time_to_crack' => '310 years', 'valid' => '310 years');
        $entropyAry[$i++] = array('days' => '114112', 'time_to_crack' => '312 years', 'valid' => '312 years');
        $entropyAry[$i++] = array('days' => '114843', 'time_to_crack' => '314 years', 'valid' => '314 years');
        $entropyAry[$i++] = array('days' => '115573', 'time_to_crack' => '316 years', 'valid' => '316 years');
        $entropyAry[$i++] = array('days' => '116304', 'time_to_crack' => '318 years', 'valid' => '318 years');
        $entropyAry[$i++] = array('days' => '117034', 'time_to_crack' => '320 years', 'valid' => '320 years');
        $entropyAry[$i++] = array('days' => '117765', 'time_to_crack' => '322 years', 'valid' => '322 years');
        $entropyAry[$i++] = array('days' => '118495', 'time_to_crack' => '324 years', 'valid' => '324 years');
        $entropyAry[$i++] = array('days' => '119226', 'time_to_crack' => '326 years', 'valid' => '326 years');
        $entropyAry[$i++] = array('days' => '119956', 'time_to_crack' => '328 years', 'valid' => '328 years');
        $entropyAry[$i++] = array('days' => '120687', 'time_to_crack' => '330 years', 'valid' => '330 years');
        $entropyAry[$i++] = array('days' => '121417', 'time_to_crack' => '332 years', 'valid' => '332 years');
        $entropyAry[$i++] = array('days' => '122148', 'time_to_crack' => '334 years', 'valid' => '334 years');
        $entropyAry[$i++] = array('days' => '122878', 'time_to_crack' => '336 years', 'valid' => '336 years');
        $entropyAry[$i++] = array('days' => '123609', 'time_to_crack' => '338 years', 'valid' => '338 years');
        $entropyAry[$i++] = array('days' => '124339', 'time_to_crack' => '340 years', 'valid' => '340 years');
        $entropyAry[$i++] = array('days' => '125070', 'time_to_crack' => '342 years', 'valid' => '342 years');
        $entropyAry[$i++] = array('days' => '125800', 'time_to_crack' => '344 years', 'valid' => '344 years');
        $entropyAry[$i++] = array('days' => '126531', 'time_to_crack' => '346 years', 'valid' => '346 years');
        $entropyAry[$i++] = array('days' => '127261', 'time_to_crack' => '348 years', 'valid' => '348 years');
        $entropyAry[$i++] = array('days' => '127992', 'time_to_crack' => '350 years', 'valid' => '350 years');
        $entropyAry[$i++] = array('days' => '128722', 'time_to_crack' => '352 years', 'valid' => '352 years');
        $entropyAry[$i++] = array('days' => '129453', 'time_to_crack' => '354 years', 'valid' => '354 years');
        $entropyAry[$i++] = array('days' => '130183', 'time_to_crack' => '356 years', 'valid' => '356 years');
        $entropyAry[$i++] = array('days' => '130914', 'time_to_crack' => '358 years', 'valid' => '358 years');
        $entropyAry[$i++] = array('days' => '131644', 'time_to_crack' => '360 years', 'valid' => '360 years');
        $entropyAry[$i++] = array('days' => '132375', 'time_to_crack' => '362 years', 'valid' => '362 years');
        $entropyAry[$i++] = array('days' => '133105', 'time_to_crack' => '364 years', 'valid' => '364 years');
        $entropyAry[$i++] = array('days' => '133836', 'time_to_crack' => '366 years', 'valid' => '366 years');
        $entropyAry[$i++] = array('days' => '134566', 'time_to_crack' => '368 years', 'valid' => '368 years');
        $entropyAry[$i++] = array('days' => '135297', 'time_to_crack' => '370 years', 'valid' => '370 years');
        $entropyAry[$i++] = array('days' => '136027', 'time_to_crack' => '372 years', 'valid' => '372 years');
        $entropyAry[$i++] = array('days' => '136758', 'time_to_crack' => '374 years', 'valid' => '374 years');
        $entropyAry[$i++] = array('days' => '137488', 'time_to_crack' => '376 years', 'valid' => '376 years');
        $entropyAry[$i++] = array('days' => '138219', 'time_to_crack' => '378 years', 'valid' => '378 years');
        $entropyAry[$i] = array('days' => '138949', 'time_to_crack' => '380 years', 'valid' => '380 years');
        return $entropyAry;
    }
}

