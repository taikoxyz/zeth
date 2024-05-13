# Raiko Docker Setup Tutorial

This tutorial was created to assist you in setting up Raiko and its SGX dependencies using a Docker container. Configuring SGX can be complex without a detailed guide to walk you through each step. This tutorial strives to provide a comprehensive walkthrough, leaving no detail unaddressed.

## Recommended Specs

We recommended 4 cores and 8GB memory for running Raiko. 8 cores and 16GB memory is ideal; the bare minimum is 2 cores and 4GB memory (tentative).

Additionally, a minimum allocation of 4GB for the "Enclave Page Cache Size" is recommended. You can check if your CPU supports this by visiting the following page: https://www.intel.com/content/www/us/en/architecture-and-technology/software-guard-extensions-processors.html

## Prerequisites

Intel SGX is a technology that involves a considerable amount of configuration. Given its high level of configurability, the setup of your infrastructure may vary significantly depending on the attestation type (EPID, ECDSA) and other parameters. While we've strived to minimize the manual effort required to prepare the development environment, there are certain prerequisites that are challenging, if not impossible, to automate using Dockerfiles. This section outlines these prerequisites.

### Intel SGX-enabled CPU

Ensure that your machine has an [Intel SGX][sgx]-enabled CPU to run Raiko. You can verify if your CPU supports SGX (Software Guard Extensions) on Linux by using the [`cpuid`][cpuid] tool.

1. If `cpuid` isn't already installed, you can install it. On Ubuntu, use the following command:

        sudo apt-get install cpuid

2. Run `cpuid` and `grep` for `sgx`:

        cpuid | grep -i sgx

    If your CPU supports SGX, the output should resemble the following:

    ```
    SGX: Software Guard Extensions supported = true
    ```

    If this line doesn't appear, your CPU either doesn't support SGX, or it isn't enabled in the BIOS.

As an alternative, you can execute `grep sgx /proc/cpuinfo`. If the command doesn't return any output, your CPU doesn't support SGX.

[sgx]: https://www.intel.com/content/www/us/en/architecture-and-technology/software-guard-extensions.html
[cpuid]: https://manpages.ubuntu.com/manpages/noble/en/man1/cpuid.1.html

### Modern Linux kernel

Starting with Linux kernel version [`5.11`][kernel-5.11], the kernel provides built-in support for SGX. However, it doesn't support one of its latest features, [EDMM][edmm] (Enclave Dynamic Memory Management), which Raiko requires. EDMM support was first introduced in Linux `6.0`, so ensure that your Linux kernel version is `6.0` or above.

To check the version of your kernel, run:

```
uname -a
```

If you're using Ubuntu and want to see the available Linux kernel versions, run the following command:

```
apt search linux-image
```

[kernel-5.11]: https://www.intel.com/content/www/us/en/developer/tools/software-guard-extensions/linux-overview.html
[edmm]: https://gramine.readthedocs.io/en/stable/manifest-syntax.html#edmm

### Subscribing to Intel PCS Service

To use ECDSA Attestation, you need to subscribe to the Intel PCS service, following the steps in [Intel's how-to guide][intel-dcap-install-howto]. After subscribing to the service, you will get two keys: a primary API key and a secondary API key.

[intel-dcap-install-howto]: https://www.intel.com/content/www/us/en/developer/articles/guide/intel-software-guard-extensions-data-center-attestation-primitives-quick-install-guide.html

> **_NOTE:_** You do NOT need to follow the entirety of the linked guide, just the `Subscribe to the Intel PCS` section.

### Verify that your SGX machine has a compatible FMSPC

At the moment Raiko only supports certain `fmspc`, so to prevent wasted time check if your machine is on our supported fmspc list.

To retrieve this information, you will need to use the `PCKIDRetrievalTool` and query the Intel API.

1. Install the `PCKIDRetrievalTool`

You can install either from the Ubuntu repository:
```
echo "deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main" | sudo tee /etc/apt/sources.list.d/intel-sgx.list > /dev/null
wget -O - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -
sudo apt update
sudo apt install sgx-pck-id-retrieval-tool
```
Or, you can [build and install][sgx-pck-id-retrieval-tool] it yourself.

2. Retrieve your machine's FMSPC by running the following command:

```shell
echo "Please enter Intel's PCS Service API key" && read -r API_KEY && PCKIDRetrievalTool -f /tmp/pckid.csv && pckid=$(cat /tmp/pckid.csv) && ppid=$(echo "$pckid" | awk -F "," '{print $1}') && cpusvn=$(echo "$pckid" | awk -F "," '{print $3}') && pcesvn=$(echo "$pckid" | awk -F "," '{print $4}') && pceid=$(echo "$pckid" | awk -F "," '{print $2}') && curl -v "https://api.trustedservices.intel.com/sgx/certification/v4/pckcert?encrypted_ppid=${ppid}&cpusvn=${cpusvn}&pcesvn=${pcesvn}&pceid=${pceid}" -H "Ocp-Apim-Subscription-Key:${API_KEY}" 2>&1 | grep -i "SGX-FMSPC"
```

<details>
<summary>Or you can retrieve FMSPC step by step</summary>


After you have installed PCKIDRetrievalTool, You should be ready to retrieve fetch Intel's certificates!

1. Run the following command:

```
PCKIDRetrievalTool
```

If successful, it should generate a `pckid_retrieval.csv`. This is a csv string which consists of:

    1. EncryptedPPID(384 BE byte array)
    2. PCE_ID(LE 16 bit integer)
    3. CPUSVN(16 byte BE byte array)
    4. PCE ISVSVN (LE 16 bit integer)
    5. QE_ID (16 byte BE byte array)

You will need this info to retrieve your FMSPC.

2. Query Intel's API to get your machine's FMSPC

```
curl -v "https://api.trustedservices.intel.com/sgx/certification/v4/pckcert?encrypted_ppid={}&cpusvn={}&pcesvn={}&pceid={}" -H "Ocp-Apim-Subscription-Key:{YOUR_API_KEY}"
```

Replace the curly braces in the above command with the values acquired from `pckid_retrieval.csv` and `YOUR_API_KEY` with your API key from subsribing to Intel's PCS Service.

The response should look as follows:

```
< HTTP/1.1 200 OK
< Content-Length: 1777
< Content-Type: application/x-pem-file
< Request-ID: e3a32aaf6cd046c69674d5bd1f1af251
< SGX-TCBm: 0B0B0303FFFF000000000000000000000D00
< SGX-PCK-Certificate-Issuer-Chain: -----BEGIN%20CERTIFICATE----- ...
-----END%20CERTIFICATE-----%0A
< SGX-PCK-Certificate-CA-Type: platform
< SGX-FMSPC: 00606A000000  <-- The FMSPC we want!
< Date: Wed, 10 Jan 2024 02:57:40 GMT
< 
-----BEGIN CERTIFICATE-----
MIIE8zCCBJmgAwIBAgIVALz+jYjxcX+fJomAUbCJqgifIol6MAoGCCqGSM49BAMC
MHAxIjAgBgNVBAMMGUludGVsIFNHWCBQQ0sgUGxhdGZvcm0gQ0ExGjAYBgNVBAoM
EUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UE
CAwCQ0ExCzAJBgNVBAYTAlVTMB4XDTI0MDExMDAyNDI0MFoXDTMxMDExMDAyNDI0
MFowcDEiMCAGA1UEAwwZSW50ZWwgU0dYIFBDSyBDZXJ0aWZpY2F0ZTEaMBgGA1UE
CgwRSW50ZWwgQ29ycG9yYXRpb24xFDASBgNVBAcMC1NhbnRhIENsYXJhMQswCQYD
VQQIDAJDQTELMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQy
sASrS6rkej14Hf1JSpuPO1NDUVyzXBCvp1h42F10UU0AFUWg1Y48oeBg7tvN5X2I
TGEB5zHBjzjv9kuWyUjUo4IDDjCCAwowHwYDVR0jBBgwFoAUlW9dzb0b4elAScnU
9DPOAVcL3lQwawYDVR0fBGQwYjBgoF6gXIZaaHR0cHM6Ly9hcGkudHJ1c3RlZHNl
cnZpY2VzLmludGVsLmNvbS9zZ3gvY2VydGlmaWNhdGlvbi92NC9wY2tjcmw/Y2E9
cGxhdGZvcm0mZW5jb2Rpbmc9ZGVyMB0GA1UdDgQWBBRTV6Zlz1vJkYSfkJj8Nifz
qgawWDAOBgNVHQ8BAf8EBAMCBsAwDAYDVR0TAQH/BAIwADCCAjsGCSqGSIb4TQEN
AQSCAiwwggIoMB4GCiqGSIb4TQENAQEEEP5GrgEczopNboM0sI0btAEwggFlBgoq
hkiG+E0BDQECMIIBVTAQBgsqhkiG+E0BDQECAQIBCzAQBgsqhkiG+E0BDQECAgIB
CzAQBgsqhkiG+E0BDQECAwIBAzAQBgsqhkiG+E0BDQECBAIBAzARBgsqhkiG+E0B
DQECBQICAP8wEQYLKoZIhvhNAQ0BAgYCAgD/MBAGCyqGSIb4TQENAQIHAgEAMBAG
CyqGSIb4TQENAQIIAgEAMBAGCyqGSIb4TQENAQIJAgEAMBAGCyqGSIb4TQENAQIK
AgEAMBAGCyqGSIb4TQENAQILAgEAMBAGCyqGSIb4TQENAQIMAgEAMBAGCyqGSIb4
TQENAQINAgEAMBAGCyqGSIb4TQENAQIOAgEAMBAGCyqGSIb4TQENAQIPAgEAMBAG
CyqGSIb4TQENAQIQAgEAMBAGCyqGSIb4TQENAQIRAgENMB8GCyqGSIb4TQENAQIS
BBALCwMD//8AAAAAAAAAAAAAMBAGCiqGSIb4TQENAQMEAgAAMBQGCiqGSIb4TQEN
AQQEBgBgagAAADAPBgoqhkiG+E0BDQEFCgEBMB4GCiqGSIb4TQENAQYEEEWJzOvy
ZE8K3kj/HhXEa/swRAYKKoZIhvhNAQ0BBzA2MBAGCyqGSIb4TQENAQcBAQH/MBAG
CyqGSIb4TQENAQcCAQH/MBAGCyqGSIb4TQENAQcDAQH/MAoGCCqGSM49BAMCA0gA
MEUCIE5VvyXrsalV8fp3Z0AbFWF4cfOJOSAaoJQLIji1TRLbAiEAsZwZGnme5EQr
n7qROhU4OOJnVs9lqNxxi8AFrJJHU2E=
-----END CERTIFICATE-----
```

</details>

Currently Supported FMSPCs:
- 00606A000000
- 00A067110000
- 00906ED50000

Please reach out to us in [discord](https://discord.com/invite/taikoxyz) channels if your machine doesn't have a listed FMSPC, if you've done the bootstrap process and obtained a quote we can try adding them to the On Chain RA process. We can't guarantee all FMSPCs will work, so you might have to switch machines.

> **_NOTE:_** At the moment, we are aware of two cloud providers who offer compatible SGX machines: [*Tencent Cloud*](https://www.tencentcloud.com/document/product/213/45510), Alibaba Cloud and Azure. (Tencent Cloud is one of our ecosystem partners!) Specifically, Tencent Cloud's `M6ce` model, Alibaba Cloud's `g7t` model support `SGX-FMSPC 00606A000000` and Azure's `confidential compute` machines support `SGX-FMSPC 00906ED50000`.

[sgx-pck-id-retrieval-tool]: https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/main/tools/PCKRetrievalTool

### Git

You will need to clone our `raiko` repository and `taiko-mono` repository to run Raiko and perform on-chain attestation to begin proving. An easy way to do this is with [git](https://git-scm.com/download/linux).

### Docker

You will need `docker` CLI installed, please find your respective distribution [here](https://docs.docker.com/engine/install/) and follow the install guide.

### Gramine

Raiko leverages [Intel SGX][sgx] via [Gramine][gramine]. As Gramine only supports [a limited number of distributions][gramine-distros], including Ubuntu. The Docker image is derived from Gramine's base image, which uses Ubuntu. Install your respective distribution [here](https://gramine.readthedocs.io/en/latest/installation.html).

[gramine-distros]: https://github.com/gramineproject/gramine/discussions/1555#discussioncomment-7016800
[gramine]: https://gramineproject.io/

## Raiko Docker

Once you have satisfied all the prerequisites, you can follow this section.

1. Prepare your system with some necessary installations

```
sudo apt-get update && sudo apt-get install -y build-essential wget python-is-python3 debhelper zip libcurl4-openssl-dev pkgconf libboost-dev libboost-system-dev libboost-thread-dev protobuf-c-compiler libprotobuf-c-dev protobuf-compiler
```

2. Generating PCCS Certificates

Before running the Raiko Docker container, you need to fulfill some SGX-specific prerequisites, which include setting up the [PCCS][pccs-readme] (Provisioning Certificate Caching Service) configuration. The PCCS service is responsible for retrieving PCK Certificates and other collaterals on-demand from the internet at runtime, and then caching them in a local database. The PCCS exposes similar HTTPS interfaces as Intel's Provisioning Certificate Service.

Begin the configuration process by [generating][pccs-cert-gen] an SSL certificate:

```
mkdir ~/.config
mkdir ~/.config/sgx-pccs
cd ~/.config/sgx-pccs
openssl genrsa -out private.pem 2048
chmod 644 private.pem  # Docker container needs access
openssl req -new -key private.pem -out csr.pem
openssl x509 -req -days 365 -in csr.pem -signkey private.pem -out file.crt
rm csr.pem
```

[pccs-readme]: https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteGeneration/pccs/README.md
[pccs-cert-gen]: https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/QuoteGeneration/pccs/container#2-generate-certificates-to-use-with-pccs

3. Install Intel lib & copy the config file

> **_NOTE:_** The library requires nodejs 18, but regardless if installation succeeds or not, we just need the `default.json` file it comes with.

```
apt install sgx-dcap-pccs
cd ~/.config/sgx-pccs
cp /opt/intel/sgx-dcap-pccs/config/default.json  .
```

Make sure you've copied the `default.json` into the .config/sgx-pccs directory you created earlier. The `raiko` container will mount this as a volume. After copying the file, open it for editing and fill in the below listed parameters as recommended by [Intel's manual][pccs-cert-gen-config]:

- `ApiKey`: The PCCS uses this API key to request collaterals from Intel's Provisioning Certificate Service. User needs to subscribe first to obtain an API key. Use either the primary or secondary key you obtained from the previous step `Subscribing to Intel PCS Service`.

- `UserTokenHash`: SHA512 hash of the user token for the PCCS client user to register a platform. For example, PCK Cert ID retrieval tool will use the user token to send platform information to PCCS. (`echo -n "user_password" | sha512sum | tr -d '[:space:]-'`).

- `AdminTokenHash`: SHA512 hash of the administrator token for the PCCS administrator to perform a manual refresh of cached artifacts (`echo -n "admin_password" | sha512sum | tr -d '[:space:]-'`).

- `hosts`: replace it with "0.0.0.0".

Ensure docker can use it by modifying permissions to the file:
 
```
chmod 644 default.json
```

[pccs-cert-gen-config]: https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/QuoteGeneration/pccs/container#3-fill-up-configuration-file

4. Make some directories to prevent errors

```
mkdir ~/.config/raiko
mkdir ~/.config/raiko/config
mkdir ~/.config/raiko/secrets
```

5. Now, clone raiko and check out the `taiko/alpha-7` branch and navigate to the `docker` folder. From here you can build the docker images that we will be using.

```
git clone -b taiko/alpha-7 https://github.com/taikoxyz/raiko.git
cd raiko/docker
docker compose build
```

> **_NOTE:_** This step will take some time, sometimes ~5 minutes.

6. Check that the images have been built

```
docker image ls
```

You should see at least two images, `gcr.io/evmchain/raiko` and `gcr.io/evmchain/pccs`.

7. If both are present, bootstrap Raiko with the following command:

```
docker compose up init
```

If everything is configured correctly, raiko-init should run without errors and generate a `bootstrap.json`. Check that it exists with the following command:

```
cat ~/.config/raiko/config/bootstrap.json
```

It should look something like this:

```
{
  "public_key": "0x0319c008667385c53cc66202eb961c624481f7317bff679d2f3c7571e06e4d9877",
  "new_instance": "0x768691497b3e5de5c5b7a8bd5e0910eba0672992",
  "quote": "03000200000000000a....................................000f00939a7"
}
```

You've now prepared your machine for running Raiko through Docker. Now, you need to perform On-Chain Remote Attestation to recieve TTKOh and begin proving for Taiko!

## On-Chain RA

1. Clone [taiko-mono](https://github.com/taikoxyz/taiko-mono/tree/main) and navigate to the scripts

```
git clone https://github.com/taikoxyz/taiko-mono.git
cd taiko-mono/packages/protocol
```

2. Install [`pnpm`](https://pnpm.io/installation#on-posix-systems) and [`foundry`](https://book.getfoundry.sh/getting-started/installation) so that you can install dependencies for taiko-mono.

```
curl -fsSL https://get.pnpm.io/install.sh | sh -
curl -L https://foundry.paradigm.xyz | bash
source ~/.bashrc
foundryup
```

Once you have installed them, run the following:

```
pnpm install
pnpm compile
```

3. Prepare your prover's private key

```
export PRIVATE_KEY={PROVER_PRIVATE_KEY} 
```

4. Ensure the values in the `script/config_dcap_sgx_verifier.sh` script match

`SGX_VERIFIER_ADDRESS`=0x532EFBf6D62720D0B2a2Bb9d11066E8588cAE6D9 
`ATTESTATION_ADDRESS`=0xC6cD3878Fc56F2b2BaB0769C580fc230A95e1398 
`PEM_CERTCHAIN_ADDRESS`=0x08d7865e7F534d743Aba5874A9AD04bcB223a92E 

5. If you've followed the Raiko Docker guide, you will have bootstrapped raiko and obtained a quote:

```
"public_key": "0x02ab85f14dcdc93832f4bb9b40ad908a5becb840d36f64d21645550ba4a2b28892",
"new_instance": "0xc369eedf4c69cacceda551390576ead2383e6f9e",
"quote": "0x030002......f00939a7233f79c4ca......9434154452d2d2d2d2d0a00"
```

Take that quote and replace `V3_QUOTE_BYTES` in the `script/config_dcap_sgx_verifier.sh` script.

6. In the `script/config_dcap_sgx_verifier.sh` script, replace `--fork-url https://any-holesky-rpc-url/` with any Holesky RPC URL.

7. Call the script with `./script/config_dcap_sgx_verifier.sh`.

> **_NOTE:_**  If you already have QE/TCB/Enclave already configured you can change `export TASK_ENABLE="1,1,1,1,1"` to `export TASK_ENABLE="0,0,0,0,1"` to only register the SGX instance.

8. If you've been successful, you will get a SGX instance `id` which can be used to run Raiko!

It should look like this:

```
emit InstanceAdded(id: 1, instance: 0xc369eedf4C69CacceDa551390576EAd2383E6f9E, replaced: 0x0000000000000000000000000000000000000000, validSince: 1708704201 [1.708e9])
```

## Running Raiko

Once you've completed the above steps, you can actually run a prover. Your `SGX_INSTANCE_ID` is the one emitted in the `InstanceAdded` event above.

```
cd ~/raiko/docker
export SGX_INSTANCE_ID={YOUR_INSTANCE_ID}
docker compose up raiko -d
```

If everything is working, you should see something like the following when executing `docker compose logs raiko`:

```
Start config:
Object {
    "address": String("0.0.0.0:8080"),
    "cache_path": Null,
    "concurrency_limit": Number(16),
    "config_path": String("/etc/raiko/config.sgx.json"),
    "log_level": String("info"),
    "log_path": Null,
    "max_log": Number(7),
    "network": String("taiko_a7"),
    "sgx": Object {
        "instance_id": Number(19), <--- sgx instance id
    },
}
Args:
Opt {
    address: "0.0.0.0:8080",
    concurrency_limit: 16,
    log_path: None,
    max_log: 7,
    config_path: "/etc/raiko/config.sgx.json",
    cache_path: None,
    log_level: "info",
}
2024-04-18T12:50:09.400319Z  INFO raiko_host::server: Listening on http://0.0.0.0:8080
```

## Verify that your Raiko instance is running properly

Once your Raiko instance is running, you can verify if it was started properly as follows:

```
 curl --location 'http://localhost:8080' \
--header 'Content-Type: application/json' \
--data '{
    "jsonrpc": "2.0",
    "method": "proof",
    "params": [
        {
            "proof_type": "sgx",
            "block_number": 31991,
            "rpc": "https://rpc.hekla.taiko.xyz/",
            "l1_rpc": "{HOLESKY_RPC_URL}",
            "beacon_rpc": "{HOLESKY_BEACON_RPC_URL}",
            "prover": "0x7b399987d24fc5951f3e94a4cb16e87414bf2229",
            "graffiti": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "sgx": {
                "setup": false,
                "bootstrap": false,
                "prove": true
            }
        }
    ],
    "id": 0
}'
```

Replace `HOLESKY_RPC_URL` and `HOLESKY_BEACON_RPC_URL` with your Holesky RPC urls.

The response should look like this:

```
{"jsonrpc":"2.0","id":0,"result":{"proof":"0x000000149f....", "quote": "03000200000000000a"}}
```

If you received this response, then at this point, your prover is up and running: you can provide the raiko_host endpoint to your taiko-client instance for SGX proving!
