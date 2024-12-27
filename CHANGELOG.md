# Changelog

## [1.5.0](https://github.com/taikoxyz/raiko/compare/v1.4.0...v1.5.0) (2024-12-27)


### Features

* complete v3 Aggregation APIs ([#424](https://github.com/taikoxyz/raiko/issues/424)) ([5dade7a](https://github.com/taikoxyz/raiko/commit/5dade7aaf2db1b76e1a4c59ce4a22f0a63bb7118))
* **host:** impl API "/admin/pause" ([#440](https://github.com/taikoxyz/raiko/issues/440)) ([ddba6b0](https://github.com/taikoxyz/raiko/commit/ddba6b0add73f05778617e3950ffafc371b9293d))
* **make:** add make help message ([#435](https://github.com/taikoxyz/raiko/issues/435)) ([bbe246b](https://github.com/taikoxyz/raiko/commit/bbe246b1932d42452afed590fe25c1066b6f0539))
* **raiko:** all-in-one dependency install script ([#427](https://github.com/taikoxyz/raiko/issues/427)) ([7139be0](https://github.com/taikoxyz/raiko/commit/7139be0fbd0afcbdac4a56e267ee0230732de4c2))
* **raiko:** make redis able to re-connect ([#432](https://github.com/taikoxyz/raiko/issues/432)) ([e530f4f](https://github.com/taikoxyz/raiko/commit/e530f4f55ec8d1e4511ac1178e4c50bdba0f2342))
* **raiko:** retry task if previous running failed. ([#408](https://github.com/taikoxyz/raiko/issues/408)) ([3432737](https://github.com/taikoxyz/raiko/commit/3432737265602098d1db546b95541542360d64e2))
* **repo:** don't run CI on draft PRs ([#428](https://github.com/taikoxyz/raiko/issues/428)) ([be2746b](https://github.com/taikoxyz/raiko/commit/be2746be5dbafd81ef49b15d3bbe102b9bd1d842))
* **repo:** run native tests on pr in taskdb dir ([#433](https://github.com/taikoxyz/raiko/issues/433)) ([9ed4ac2](https://github.com/taikoxyz/raiko/commit/9ed4ac2958eaf742d8c191ef73b9f9ed510e202b))
* **taskdb:** remove sqlite task manager ([#423](https://github.com/taikoxyz/raiko/issues/423)) ([89f748f](https://github.com/taikoxyz/raiko/commit/89f748f67eb78383ec978e156e5511a721af4e71))
* union proof type relevant stuff ([#422](https://github.com/taikoxyz/raiko/issues/422)) ([4b0df41](https://github.com/taikoxyz/raiko/commit/4b0df4105f2b599d88455fc020d25eaa5a0d7c3d))


### Bug Fixes

* bump sp1 version + new patch ([#412](https://github.com/taikoxyz/raiko/issues/412)) ([64fd81f](https://github.com/taikoxyz/raiko/commit/64fd81f09a7305412286942ab0abb7cb8086c394))
* **host:** limit body size using DefaultBodyLimit ([#437](https://github.com/taikoxyz/raiko/issues/437)) ([a720df5](https://github.com/taikoxyz/raiko/commit/a720df594a48abf63b96828462a512aec85cca9e))
* **raiko:** avoid duplicate image uploads ([#439](https://github.com/taikoxyz/raiko/issues/439)) ([5804f23](https://github.com/taikoxyz/raiko/commit/5804f23298b832d956070c8f4f656f8c039e788e))
* **raiko:** fix some misleading info prints ([#425](https://github.com/taikoxyz/raiko/issues/425)) ([32bc6a9](https://github.com/taikoxyz/raiko/commit/32bc6a994e4ce26f3bac1aebf7c7e60facd8e909))
* **repo:** missed one workflow ([#429](https://github.com/taikoxyz/raiko/issues/429)) ([0c22438](https://github.com/taikoxyz/raiko/commit/0c22438527c819eec046b5e61c84ccc3c4551e4e))


### Performance Improvements

* **host:** release running_tasks lock asap ([#417](https://github.com/taikoxyz/raiko/issues/417)) ([6e98484](https://github.com/taikoxyz/raiko/commit/6e984840a8038a6654ab1ecbb1caea7c036feb3a))

## [1.4.0](https://github.com/taikoxyz/raiko/compare/v1.3.0...v1.4.0) (2024-11-11)


### Features

* **docs:** use edmm image ([#402](https://github.com/taikoxyz/raiko/issues/402)) ([450eef6](https://github.com/taikoxyz/raiko/commit/450eef6ee7b71adc148d956b2f9dd9725999654f))
* introduce file lock for share instance bootstrap ([#405](https://github.com/taikoxyz/raiko/issues/405)) ([9317ca1](https://github.com/taikoxyz/raiko/commit/9317ca1eb99a8a1d67a3aaf107a76c00f9cfdeb1))
* **raiko:** add alloc feature to compile risc0 guest to avoid oom issue ([#404](https://github.com/taikoxyz/raiko/issues/404)) ([831efbe](https://github.com/taikoxyz/raiko/commit/831efbe9308e73fbdb86d7790c4a56333f4090fe))
* **raiko:** config redis ttl from cmdline & default 1 hour ([#406](https://github.com/taikoxyz/raiko/issues/406)) ([a497171](https://github.com/taikoxyz/raiko/commit/a4971711932ca3c1429a0a6e306c5bfd9523c7aa))
* **raiko:** multi blocks in one proposal tx ([#403](https://github.com/taikoxyz/raiko/issues/403)) ([d85cb13](https://github.com/taikoxyz/raiko/commit/d85cb13675604ecd75cf373b41576d3b146e7e14))
* **raiko:** redis db implementation for sharing proof between cloud instances. ([#389](https://github.com/taikoxyz/raiko/issues/389)) ([14b15e6](https://github.com/taikoxyz/raiko/commit/14b15e68aa986840f1ffcd64704c4a22f4e73aa6))


### Bug Fixes

* **raiko:** fix task db report and docker image build ([#400](https://github.com/taikoxyz/raiko/issues/400)) ([54291f3](https://github.com/taikoxyz/raiko/commit/54291f364132832a7462edceffdb8c44ac9d3de9))

## [1.3.0](https://github.com/taikoxyz/raiko/compare/v1.2.0...v1.3.0) (2024-10-23)


### Features

* **core,host:** initial aggregation API ([#375](https://github.com/taikoxyz/raiko/issues/375)) ([eb4d032](https://github.com/taikoxyz/raiko/commit/eb4d032abf7c55d3d1d498b8f08a00250fe0a14a))
* **docs:** update docs for 1.2.0 ([#382](https://github.com/taikoxyz/raiko/issues/382)) ([f33d211](https://github.com/taikoxyz/raiko/commit/f33d2119a66864bb34ca915349c06f6e950c94ce))
* **raiko:** enable blob slice to support multi-blocks in single blob ([#390](https://github.com/taikoxyz/raiko/issues/390)) ([8471b16](https://github.com/taikoxyz/raiko/commit/8471b16bfe86b1d4a18a8092ab40cb5488ff824f))
* **raiko:** merge stress test upgrades ([#392](https://github.com/taikoxyz/raiko/issues/392)) ([7f64cbe](https://github.com/taikoxyz/raiko/commit/7f64cbe72176f2f4a424c31a7946171d48d89537))
* **raiko:** put the tasks that cannot run in parallel into pending list ([#358](https://github.com/taikoxyz/raiko/issues/358)) ([ec483b7](https://github.com/taikoxyz/raiko/commit/ec483b7e6d637b921e677ad7fb89222da7749b85))
* **raiko:** update ontake config & docker build for next release ([#394](https://github.com/taikoxyz/raiko/issues/394)) ([4bacdac](https://github.com/taikoxyz/raiko/commit/4bacdac7ec4c28e0fad9594093840226775a7e26))
* **raiko:** use simple contract to verify sp1 proof ([#381](https://github.com/taikoxyz/raiko/issues/381)) ([8ad5a6f](https://github.com/taikoxyz/raiko/commit/8ad5a6f1e73ad57183e353b18649baa977752206))


### Bug Fixes

* add cgroup&mountinfo for docker env ([#383](https://github.com/taikoxyz/raiko/issues/383)) ([7e61432](https://github.com/taikoxyz/raiko/commit/7e614326b199d350c24f83dd27ac08d878f105cb))
* incorrect state transition handling ([#395](https://github.com/taikoxyz/raiko/issues/395)) ([6d1f3ae](https://github.com/taikoxyz/raiko/commit/6d1f3ae8c5bc2131cd79a5023335bc845095dee4))
* **raiko:** add build flags to docker image build script ([#379](https://github.com/taikoxyz/raiko/issues/379)) ([2ee7d2a](https://github.com/taikoxyz/raiko/commit/2ee7d2ac1762f088c06df80d187dcfc00cfba882))
* **raiko:** fix r0 aggregation proof format ([#386](https://github.com/taikoxyz/raiko/issues/386)) ([3cb6651](https://github.com/taikoxyz/raiko/commit/3cb6651d4adc443697473e33e24a849516e9b264))

## [1.2.0](https://github.com/taikoxyz/raiko/compare/v1.1.0...v1.2.0) (2024-09-20)


### Features

* **raiko:** make raiko-zk docker image ([#374](https://github.com/taikoxyz/raiko/issues/374)) ([65ff9a4](https://github.com/taikoxyz/raiko/commit/65ff9a4935ac66f0c21785a0b8415313942bda82))
* **raiko:** traversal to find inclusion block if none inclusion number is sent ([#377](https://github.com/taikoxyz/raiko/issues/377)) ([c2b0db5](https://github.com/taikoxyz/raiko/commit/c2b0db5a61e920840f9de083de8684a8375e51b3))
* **sgx:** add wallet to provider builder when register instance ([#369](https://github.com/taikoxyz/raiko/issues/369)) ([a250edf](https://github.com/taikoxyz/raiko/commit/a250edf2ca42d5481ba92d97ca6ade5b46bb536c))


### Bug Fixes

* **raiko:** refine error return ([#378](https://github.com/taikoxyz/raiko/issues/378)) ([f4f818d](https://github.com/taikoxyz/raiko/commit/f4f818d43a33ba1caf95cb1db4160ba90824eb2d))
* **script:** output build message and skip `pos` flag ([#367](https://github.com/taikoxyz/raiko/issues/367)) ([2c881dc](https://github.com/taikoxyz/raiko/commit/2c881dc22d5df553bffc24f8bbac6a86e2fd9688))

## [1.1.0](https://github.com/taikoxyz/raiko/compare/v1.0.0...v1.1.0) (2024-09-13)


### Features

* **ci:** fix make clippy script and clippy CI job ([#220](https://github.com/taikoxyz/raiko/issues/220)) ([62158a0](https://github.com/taikoxyz/raiko/commit/62158a097221f3676ad3bed61070a9e967966e81))
* **devnet:** update devnet config ([#326](https://github.com/taikoxyz/raiko/issues/326)) ([959bdea](https://github.com/taikoxyz/raiko/commit/959bdeadfc216e76ee512cab38f9ab560dea237c))
* **docs:** check epc size instructions and script ([#342](https://github.com/taikoxyz/raiko/issues/342)) ([4235d32](https://github.com/taikoxyz/raiko/commit/4235d326140bb4f695ec63425b160adad1df645b))
* **docs:** update tencent link ([#269](https://github.com/taikoxyz/raiko/issues/269)) ([1e2a254](https://github.com/taikoxyz/raiko/commit/1e2a2541111d70352aaefc4c629f9daea58ce6e4))
* **harness:** make harness part of the root workspace ([#285](https://github.com/taikoxyz/raiko/issues/285)) ([e3d2403](https://github.com/taikoxyz/raiko/commit/e3d2403b643e87093a547837234d9bf13dfb03ce))
* **host,provers,tasks:** handle local job cancellation ([#345](https://github.com/taikoxyz/raiko/issues/345)) ([cce1371](https://github.com/taikoxyz/raiko/commit/cce137114cbae69cf975a37119fb053378e9913c))
* **host:** create initial cancel handling ([#316](https://github.com/taikoxyz/raiko/issues/316)) ([f6d02b3](https://github.com/taikoxyz/raiko/commit/f6d02b3d3397a88e0029a18af66dd54461561916))
* **host:** extract worker message handling ([#307](https://github.com/taikoxyz/raiko/issues/307)) ([ae8858c](https://github.com/taikoxyz/raiko/commit/ae8858c58e0fd099ec4a81d55270a0bfd8521df7))
* **misc:** remove sp1-helper from builder ([#293](https://github.com/taikoxyz/raiko/issues/293)) ([fd474e3](https://github.com/taikoxyz/raiko/commit/fd474e3304edd896305260feec47641a826e1521))
* prepare for ontake upgrade ([#329](https://github.com/taikoxyz/raiko/issues/329)) ([9546df7](https://github.com/taikoxyz/raiko/commit/9546df70719e036d7abf6073ed50bd2c59ea23c8))
* prove blocks using reth ([#226](https://github.com/taikoxyz/raiko/issues/226)) ([546ab19](https://github.com/taikoxyz/raiko/commit/546ab19cbc12e58a10ede52076d5b6bbcd093f1a))
* **prover:** bls12-381 & updates patches ([#350](https://github.com/taikoxyz/raiko/issues/350)) ([7356e8f](https://github.com/taikoxyz/raiko/commit/7356e8fd289fd6539b94c8d28366b49a410da647))
* **prover:** change GuestOutput and the zk committed value for onchain verification ([#282](https://github.com/taikoxyz/raiko/issues/282)) ([37f6c49](https://github.com/taikoxyz/raiko/commit/37f6c4970924ebb9d53941498ba69123ab304c48))
* **prover:** enable GuestInput serialization in native path ([#281](https://github.com/taikoxyz/raiko/issues/281)) ([0ba89ae](https://github.com/taikoxyz/raiko/commit/0ba89aecf846e2aeda41ff0c65410b9beb0d77f6))
* **prover:** sp1 onchain verifier ([#229](https://github.com/taikoxyz/raiko/issues/229)) ([1f0b062](https://github.com/taikoxyz/raiko/commit/1f0b0623b581fe16242972c12e58def54352b436))
* **provers:** update Sp1 v1.0.1 ([#333](https://github.com/taikoxyz/raiko/issues/333)) ([e85c0d2](https://github.com/taikoxyz/raiko/commit/e85c0d275ce7b1f65ba0c2460ff78da260b244b5))
* **prover:** track cycles of sp1 guest & patch Secp256k1 ([#288](https://github.com/taikoxyz/raiko/issues/288)) ([927e697](https://github.com/taikoxyz/raiko/commit/927e6973ae2ba8c68b18cb7e53a719c1eaee5896))
* **raiko-lib:** unify protocol instance for on chain verification ([#230](https://github.com/taikoxyz/raiko/issues/230)) ([ed37856](https://github.com/taikoxyz/raiko/commit/ed37856906bf27433418e7a781d4138b180da550))
* **raiko:** bonsai auto scaling ([#341](https://github.com/taikoxyz/raiko/issues/341)) ([dc89e60](https://github.com/taikoxyz/raiko/commit/dc89e60ae1b30837b2cc1a45faec30969d3ec144))
* **raiko:** config hekla ontake fork ([#366](https://github.com/taikoxyz/raiko/issues/366)) ([80915d8](https://github.com/taikoxyz/raiko/commit/80915d88c710fbaae8f9f4074aa6028724eeb079))
* **raiko:** prove risc0 proof in devnet ([#335](https://github.com/taikoxyz/raiko/issues/335)) ([dcbad01](https://github.com/taikoxyz/raiko/commit/dcbad01194159d1b0f8a56f9dad9db0253b49cd1))
* **raiko:** refine auto-scaling ([#346](https://github.com/taikoxyz/raiko/issues/346)) ([34c1348](https://github.com/taikoxyz/raiko/commit/34c1348cb3f001638488c74c5fded0b2a38c101e))
* **raiko:** refine error return to avoid incorrect status. ([#348](https://github.com/taikoxyz/raiko/issues/348)) ([829609c](https://github.com/taikoxyz/raiko/commit/829609c9687eaaf55e1bce6ebd6fe454a0ad1ffc))
* **raiko:** rename tasks manager ([#318](https://github.com/taikoxyz/raiko/issues/318)) ([9568634](https://github.com/taikoxyz/raiko/commit/956863408171c4cd6b0f241828d54222ef663dad))
* **raiko:** update risc0 toolchain to v1.0.1 ([#311](https://github.com/taikoxyz/raiko/issues/311)) ([d2b87e0](https://github.com/taikoxyz/raiko/commit/d2b87e060097be26da622e43273fc036e15602af))
* **raiko:** use even more reth ([#303](https://github.com/taikoxyz/raiko/issues/303)) ([a51fd42](https://github.com/taikoxyz/raiko/commit/a51fd424b9a1b37e08e6b7580fae314fdfede9a6))
* **raiko:** use feature to enable proof-of-equivalence ([#317](https://github.com/taikoxyz/raiko/issues/317)) ([22637d0](https://github.com/taikoxyz/raiko/commit/22637d0b1894b0b344f611e4b33053f744f6fb37))
* **repo:** ignore changes to docs for build ([#343](https://github.com/taikoxyz/raiko/issues/343)) ([b901ce6](https://github.com/taikoxyz/raiko/commit/b901ce6742888552a502ba62b0b179f91588f4e0))
* **task db:** implement a task DB ([#208](https://github.com/taikoxyz/raiko/issues/208)) ([48ea079](https://github.com/taikoxyz/raiko/commit/48ea0792b94e2973ece698b50452d3b46310d952))
* **tasks:** add README & return the latest status only from POST 'proof/report' ([#319](https://github.com/taikoxyz/raiko/issues/319)) ([f7cab97](https://github.com/taikoxyz/raiko/commit/f7cab9737483dc5030dd1a9f61e9d09093b9911c))
* update docs ([#324](https://github.com/taikoxyz/raiko/issues/324)) ([fee3869](https://github.com/taikoxyz/raiko/commit/fee3869079efd6e50623be37951697a820582150))


### Bug Fixes

* **bonsai:** handle error unwrapping gracefully ([#339](https://github.com/taikoxyz/raiko/issues/339)) ([f396354](https://github.com/taikoxyz/raiko/commit/f396354566e62d53df88d60e7cc456e5f0fbc4cf))
* **host:** add guest request count and make concurrent request decrementation more ergonomic ([#261](https://github.com/taikoxyz/raiko/issues/261)) ([d660a17](https://github.com/taikoxyz/raiko/commit/d660a17c9fef9ce9fa58558a4d3da115d134dad6))
* **host:** ignore `no id found` error for cancellation ([#330](https://github.com/taikoxyz/raiko/issues/330)) ([048df9f](https://github.com/taikoxyz/raiko/commit/048df9f840ea40742f3e14106c9352b835b11628))
* **lib,provers,tasks:** move from sync to async trait ([#328](https://github.com/taikoxyz/raiko/issues/328)) ([36a5614](https://github.com/taikoxyz/raiko/commit/36a56145b25c3b18fbcd3af5b1f2ab71b521cba3))
* **raiko:** double check if cached file is valid. ([#271](https://github.com/taikoxyz/raiko/issues/271)) ([39bdc11](https://github.com/taikoxyz/raiko/commit/39bdc11d46814f6f9876c54df29c631ad2127b74))
* **raiko:** fix fixture dir and update sp1 contract test ([#353](https://github.com/taikoxyz/raiko/issues/353)) ([ecbd621](https://github.com/taikoxyz/raiko/commit/ecbd6212e11183c1d76706734efb8a02b1bb52c7))
* **raiko:** removed panic stabilization ([#232](https://github.com/taikoxyz/raiko/issues/232)) ([254ff6a](https://github.com/taikoxyz/raiko/commit/254ff6a90d1ea17672d2cf6352cb6a9af98f0ec0))
* **raiko:** revert v1 response back to previous format ([#340](https://github.com/taikoxyz/raiko/issues/340)) ([5526cc0](https://github.com/taikoxyz/raiko/commit/5526cc04ae5b2c4b9d31d59f56e7e8bb68c75668))
* **raiko:** run ci checks on merge queue ([#305](https://github.com/taikoxyz/raiko/issues/305)) ([1d69947](https://github.com/taikoxyz/raiko/commit/1d6994702ebade7450cd418727ec8e2b073861c7))
* **raiko:** set default behavior and fix proof format ([#354](https://github.com/taikoxyz/raiko/issues/354)) ([5533914](https://github.com/taikoxyz/raiko/commit/55339149daeee14b394ea6158d8cdfa5824b344c))
* **raiko:** unsafe align vec to avoid unalign mem access ([#291](https://github.com/taikoxyz/raiko/issues/291)) ([5e9dbe8](https://github.com/taikoxyz/raiko/commit/5e9dbe82c798c2e48051b5976a459cec6c700385))

## 1.0.0 (2024-05-25)


### Features

* add jwt secret for authentication ([#243](https://github.com/taikoxyz/raiko/issues/243)) ([78a633d](https://github.com/taikoxyz/raiko/commit/78a633da60c712c7338988d49031ff401a09d24f))
* add sgx input file lock to avoid concurrency problem ([9df1473](https://github.com/taikoxyz/raiko/commit/9df147394aa5e2c48a92364fcc037191faa914fd))
* Always respond with 200 but include status key ([#214](https://github.com/taikoxyz/raiko/issues/214)) ([9c13a4f](https://github.com/taikoxyz/raiko/commit/9c13a4fcb5e466ff0e190b52160c5d42b71f67e9))
* batch get 256 history headers ([#95](https://github.com/taikoxyz/raiko/issues/95)) ([fd3434a](https://github.com/taikoxyz/raiko/commit/fd3434aa72766e9cb0a74e20a2bfe784743ebbe2))
* let user setup which network to run ([#246](https://github.com/taikoxyz/raiko/issues/246)) ([9f80be5](https://github.com/taikoxyz/raiko/commit/9f80be559396dc1daccf3bce6f38b9b628d0a76e))
* lock the setup for sharing instance ([#244](https://github.com/taikoxyz/raiko/issues/244)) ([04d3197](https://github.com/taikoxyz/raiko/commit/04d31975f5417d3cb4357213174dbad3c178f81a))
* **raiko:** api versioning ([#196](https://github.com/taikoxyz/raiko/issues/196)) ([09e0005](https://github.com/taikoxyz/raiko/commit/09e0005d66d6e86d38381cab19c3990c1b0b7bae))
* **raiko:** Cherry-pick A7 updates([#182](https://github.com/taikoxyz/raiko/issues/182)) ([#197](https://github.com/taikoxyz/raiko/issues/197)) ([b3c2c1d](https://github.com/taikoxyz/raiko/commit/b3c2c1d9136348004f0a8653538cadf2743e8873))
* **raiko:** ci use sgx hw ([#175](https://github.com/taikoxyz/raiko/issues/175)) ([a40be21](https://github.com/taikoxyz/raiko/commit/a40be21d33d94414e4dc6259e17939785be69204))
* **raiko:** ci use sgx hw ([#175](https://github.com/taikoxyz/raiko/issues/175)) ([b7c44de](https://github.com/taikoxyz/raiko/commit/b7c44dedb784b39df9cbd7c87277f8355fa2fd50))
* **raiko:** enable kzg blob check ([#148](https://github.com/taikoxyz/raiko/issues/148)) ([9865b4c](https://github.com/taikoxyz/raiko/commit/9865b4cb91a56cbf0678d494cbea624f6ef0b067))
* **raiko:** generalized build pipeline for ZkVMs guests ([#133](https://github.com/taikoxyz/raiko/issues/133)) ([9cebd36](https://github.com/taikoxyz/raiko/commit/9cebd36a44c7243195b9cc1ef72ef2e949157dc1))
* **raiko:** install script + makefile CI integration ([#159](https://github.com/taikoxyz/raiko/issues/159)) ([a6c1095](https://github.com/taikoxyz/raiko/commit/a6c10953326b449127f6dcda2b92d2b1747c7f2d))
* **raiko:** load program from elf for risc zero ([#194](https://github.com/taikoxyz/raiko/issues/194)) ([dc0a427](https://github.com/taikoxyz/raiko/commit/dc0a4279cb8ad13cce54ce5ef182fe57509a6e3a))
* **raiko:** raiko object ([#149](https://github.com/taikoxyz/raiko/issues/149)) ([c4215bd](https://github.com/taikoxyz/raiko/commit/c4215bde45675d57e7a16f32107146b3b9756e75))
* **raiko:** read & merge chain spec from a optional config file ([#206](https://github.com/taikoxyz/raiko/issues/206)) ([4c76667](https://github.com/taikoxyz/raiko/commit/4c766678d8b0d1d9ba038e1f1be53679b25db05a))
* **raiko:** remove A6 support ([#200](https://github.com/taikoxyz/raiko/issues/200)) ([250b9ea](https://github.com/taikoxyz/raiko/commit/250b9ea21760442230573246a307c12816f42491))
* **raiko:** run general tests on all targets ([#164](https://github.com/taikoxyz/raiko/issues/164)) ([27b0bee](https://github.com/taikoxyz/raiko/commit/27b0beeaace5b93d1d32ac9b13da0722793fafeb))
* **raiko:** unity sgx & native proof response ([#223](https://github.com/taikoxyz/raiko/issues/223)) ([bead6e9](https://github.com/taikoxyz/raiko/commit/bead6e93542e264fae5c9faca7c726c8bd8d4ede))
* **raiko:** update chain spec ([#235](https://github.com/taikoxyz/raiko/issues/235)) ([8f21a69](https://github.com/taikoxyz/raiko/commit/8f21a690d82d3bc570bcc84f2ed4fa87a17ba6d7))
* **raiko:** update docker build ([#225](https://github.com/taikoxyz/raiko/issues/225)) ([e58c082](https://github.com/taikoxyz/raiko/commit/e58c082daf874ad57a60624ea92f29714a8f4c62))
* use batch api instead of customize api for history headers ([49d147f](https://github.com/taikoxyz/raiko/commit/49d147f54fc187a0cffd1767af47fcc5783496a6))
* use spec in setup ([#236](https://github.com/taikoxyz/raiko/issues/236)) ([cd097a5](https://github.com/taikoxyz/raiko/commit/cd097a5cca62ef8a7b8a40991939ff740e00dd22))
* use stdin instead of sgx tmp file ([0d33aa8](https://github.com/taikoxyz/raiko/commit/0d33aa81fadeab27e45e6632defa0e0d8ce293d4))


### Bug Fixes

* can't share setup between pods ([#253](https://github.com/taikoxyz/raiko/issues/253)) ([0d7be6b](https://github.com/taikoxyz/raiko/commit/0d7be6b2c8979f2eeedf458e71ee0f5a6787d14f))
* different manifest in docker and local ([#117](https://github.com/taikoxyz/raiko/issues/117)) ([52999d6](https://github.com/taikoxyz/raiko/commit/52999d664a44ad86f4a69392f76353fc656821ff))
* docker stuff ([#241](https://github.com/taikoxyz/raiko/issues/241)) ([6bb70b1](https://github.com/taikoxyz/raiko/commit/6bb70b15991060dba5620f7903a18008a02b43e3))
* enable the mpt cache ([#62](https://github.com/taikoxyz/raiko/issues/62)) ([46825d6](https://github.com/taikoxyz/raiko/commit/46825d66a2edfc8ce0e2acfb2e6e272645d79956))
* fetch history headers ([#100](https://github.com/taikoxyz/raiko/issues/100)) ([4fd70ee](https://github.com/taikoxyz/raiko/commit/4fd70eee7b5a64173549d3e466ab4bd7fbf2a33b))
* install sudo for gramine ([#250](https://github.com/taikoxyz/raiko/issues/250)) ([4f78b0a](https://github.com/taikoxyz/raiko/commit/4f78b0ab264399c789bd98f51a3ea238a704146b))
* let config_path in config_dir ([#233](https://github.com/taikoxyz/raiko/issues/233)) ([78a5844](https://github.com/taikoxyz/raiko/commit/78a584406dde604b73b74e8269a7017cf6fb0098))
* **lib:** temporarily disable kzg check in sgx/sp1 provers ([#157](https://github.com/taikoxyz/raiko/issues/157)) ([039d2fa](https://github.com/taikoxyz/raiko/commit/039d2fae62a7ec7d66c40d73cc1a47c65bf87c23))
* metrics docker fix ([#216](https://github.com/taikoxyz/raiko/issues/216)) ([86bbc55](https://github.com/taikoxyz/raiko/commit/86bbc5598ee58194951a86c1775dfb30a3fed31b))
* mismatch method signature of libc's calloc ([#201](https://github.com/taikoxyz/raiko/issues/201)) ([ecde21d](https://github.com/taikoxyz/raiko/commit/ecde21da99ceeb273c3df736a152e9e6ab5ea23d))
* **raiko:** fix sticky invalid tx state ([#184](https://github.com/taikoxyz/raiko/issues/184)) ([99f5580](https://github.com/taikoxyz/raiko/commit/99f558088437af32e76e04d0529ea0715a163d40))
* **raiko:** make kzg work on SP1 ([#205](https://github.com/taikoxyz/raiko/issues/205)) ([027c3ae](https://github.com/taikoxyz/raiko/commit/027c3aee910a7a0cae1dec4eb19b7865d4aa5c0d))
* revm bn254 mul issue + cancun support + misc issues ([#222](https://github.com/taikoxyz/raiko/issues/222)) ([d90acd0](https://github.com/taikoxyz/raiko/commit/d90acd00be42b6af4a7f0301882d8719be5fdf64))
* use json num instead of string ([#252](https://github.com/taikoxyz/raiko/issues/252)) ([9bcb44a](https://github.com/taikoxyz/raiko/commit/9bcb44a19b8a99224c6e047ee02c6fd5e8b8c177))


### Performance Improvements

* only filter once ([e1f5d41](https://github.com/taikoxyz/raiko/commit/e1f5d411a496a6d563ae8db61b164a0b77928884))
