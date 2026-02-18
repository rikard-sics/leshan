<edhoc-input>
    <!-- EDHOC inputs -->
    
    <!-- TODO: Add validation -->
    
    <button type="button" onclick="
         document.getElementById('initiator').value = 'True';
         document.getElementById('authenticationMethod').value = '0';
         document.getElementById('selectedCiphersuite').value = '2';
         document.getElementById('clientKeyIdentifier').value = '07';
         document.getElementById('clientPublicKey').value = 'a2027734322d35302d33312d46462d45462d33372d33322d333908a101a5010202412b2001215820ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb62258206e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8';
         document.getElementById('privateKey').value = 'fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b';
         document.getElementById('peerPublicKeyIdentifier').value = '24';
         document.getElementById('peerPublicKey').value = 'a2026b6578616d706c652e65647508a101a501020241322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072';
         document.getElementById('peerEdhocCoapUriPath').value = '.well-known/edhoc';
         document.getElementById('edhocOscoreCombinedSupport').value = 'False';
         
         document.getElementById('initiator').innerHTML = 'True';
         document.getElementById('authenticationMethod').innerHTML = '0';
         document.getElementById('selectedCiphersuite').innerHTML = '2';
         document.getElementById('clientKeyIdentifier').innerHTML = '07';
         document.getElementById('clientPublicKey').innerHTML = 'a2027734322d35302d33312d46462d45462d33372d33322d333908a101a5010202412b2001215820ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb62258206e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8';
         document.getElementById('privateKey').innerHTML = 'fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b';
         document.getElementById('peerPublicKeyIdentifier').innerHTML = '24';
         document.getElementById('peerPublicKey').innerHTML = 'a2026b6578616d706c652e65647508a101a501020241322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072';
         document.getElementById('peerEdhocCoapUriPath').innerHTML = '.well-known/edhoc';
         document.getElementById('edhocOscoreCombinedSupport').innerHTML = 'False';
         
         document.getElementById('initiator').innerText = 'True';
         document.getElementById('authenticationMethod').innerText = '0';
         document.getElementById('selectedCiphersuite').innerText = '2';
         document.getElementById('clientKeyIdentifier').innerText = '07';
         document.getElementById('clientPublicKey').innerText = 'a2027734322d35302d33312d46462d45462d33372d33322d333908a101a5010202412b2001215820ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb62258206e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8';
         document.getElementById('privateKey').innerText = 'fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b';
         document.getElementById('peerPublicKeyIdentifier').innerText = '24';
         document.getElementById('peerPublicKey').innerText = 'a2026b6578616d706c652e65647508a101a501020241322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072';
         document.getElementById('peerEdhocCoapUriPath').innerText = '.well-known/edhoc';
         document.getElementById('edhocOscoreCombinedSupport').innerText = 'False';
    ">Fill Client<->DM config</button> 
         
    <button type="button" hidden onclick="
         document.getElementById('initiator').value = 'True';
         document.getElementById('authenticationMethod').value = '0';
         document.getElementById('selectedCiphersuite').value = '2';
         document.getElementById('clientKeyIdentifier').value = '08';
         document.getElementById('clientPublicKey').value = 'a2027734322d35302d33312d46462d45462d33372d33322d333908a101a5010202412b2001215820ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb62258206e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8';
         document.getElementById('privateKey').value = 'fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b';
         document.getElementById('peerPublicKeyIdentifier').value = '25';
         document.getElementById('peerPublicKey').value = 'a2026b6578616d706c652e65647508a101a501020241322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072';
         document.getElementById('edhocOscoreCombinedSupport').value = 'False';
         
         document.getElementById('initiator').innerText = 'True';
         document.getElementById('authenticationMethod').innerText = '0';
         document.getElementById('selectedCiphersuite').innerText = '2';
         document.getElementById('clientKeyIdentifier').innerText = '08';
         document.getElementById('clientPublicKey').innerText = 'a2027734322d35302d33312d46462d45462d33372d33322d333908a101a5010202412b2001215820ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb62258206e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8';
         document.getElementById('privateKey').innerText = 'fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b';
         document.getElementById('peerPublicKeyIdentifier').innerText = '25';
         document.getElementById('peerPublicKey').innerText = 'a2026b6578616d706c652e65647508a101a501020241322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072';
         document.getElementById('edhocOscoreCombinedSupport').innerText = 'False';
         
         document.getElementById('initiator').innerHTML = 'True';
         document.getElementById('authenticationMethod').innerHTML = '0';
         document.getElementById('selectedCiphersuite').innerHTML = '2';
         document.getElementById('clientKeyIdentifier').innerHTML = '08';
         document.getElementById('clientPublicKey').innerHTML = 'a2027734322d35302d33312d46462d45462d33372d33322d333908a101a5010202412b2001215820ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb62258206e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8';
         document.getElementById('privateKey').innerHTML = 'fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b';
         document.getElementById('peerPublicKeyIdentifier').innerHTML = '25';
         document.getElementById('peerPublicKey').innerHTML = 'a2026b6578616d706c652e65647508a101a501020241322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072';
         document.getElementById('edhocOscoreCombinedSupport').innerHTML = 'False';
    ">Fill Client<->AS config</button> 
    
    
    <div class={ form-group:true }>
        <label for="peerPublicKeyIdentifier" class="col-sm-4 control-label">Peer Public Key Identifier</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="1" id="peerPublicKeyIdentifier" ref="peerPublicKeyIdentifier"></textarea>
            <p class="text-right text-muted small" style="margin:0">Hexadecimal format</p>
        </div>
    </div>

    <div class={ form-group:true }>
        <label for="peerPublicKey" class="col-sm-4 control-label">Peer Public Key</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="5" id="peerPublicKey" ref="peerPublicKey"></textarea>
            <p class="text-right text-muted small" style="margin:0">Hexadecimal format</p>
        </div>
    </div>
    
    <div class={ form-group:true }>
        <label for="clientKeyIdentifier" class="col-sm-4 control-label">Client Key Identifier</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="1" id="clientKeyIdentifier" ref="clientKeyIdentifier"></textarea>
            <p class="text-right text-muted small" style="margin:0">Hexadecimal format</p>
        </div>
    </div>

    <div class={ form-group:true }>
        <label for="clientPublicKey" class="col-sm-4 control-label">Client Public Key</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="5" id="clientPublicKey" ref="clientPublicKey"></textarea>
            <p class="text-right text-muted small" style="margin:0">Hexadecimal format</p>
        </div>
    </div>

    <div class={ form-group:true }>
        <label for="privateKey" class="col-sm-4 control-label">Private Key</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="2" id="privateKey" ref="privateKey"></textarea>
            <p class="text-right text-muted small" style="margin:0">Hexadecimal format</p>
        </div>
    </div>
    
    <div class={ form-group:true }>
        <label for="authenticationMethod" class="col-sm-4 control-label">Method</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="1" id="authenticationMethod" ref="authenticationMethod"></textarea>
        </div>
    </div>
    
    <div class={ form-group:true }>
        <label for="initiator" class="col-sm-4 control-label">Initiator</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="1" id="initiator" ref="initiator"></textarea>
        </div>
    </div>
    
    <div class={ form-group:true }>
        <label for="selectedCiphersuite" class="col-sm-4 control-label">Selected Ciphersuite</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="1" id="selectedCiphersuite" ref="selectedCiphersuite"></textarea>
        </div>
    </div>

    <div class={ form-group:true }>
        <label for="peerEdhocCoapUriPath" class="col-sm-4 control-label">Peer EDHOC CoAP URI Path</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="1" id="peerEdhocCoapUriPath" ref="peerEdhocCoapUriPath"></textarea>
        </div>
    </div>

    <div class={ form-group:true }>
        <label for="edhocOscoreCombinedSupport" class="col-sm-4 control-label">EDHOC OSCORE Combined Support</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="1" id="edhocOscoreCombinedSupport" ref="edhocOscoreCombinedSupport"></textarea>
        </div>
    </div>


    <script>
        // Tag definition
        var tag = this;
        // Tag Params
        tag.onchange = opts.onchange;
        // Tag API
        tag.has_error = has_error;
        tag.get_value = get_value
        // Tag internal state
        tag.masterSecret={};
        tag.masterSalt={};
        tag.senderId={};
        tag.recipientId={};
        tag.aeadAlgorithm={};
        tag.defaultAeadAlgorithm = "AES_CCM_16_64_128";
        tag.hkdfAlgorithm={};
        tag.defaultHkdfAlgorithm = "HKDF_HMAC_SHA_256";
        tag.validate_masterSecret = validate_masterSecret;
        tag.validate_masterSalt = validate_masterSalt;
        tag.validate_senderId = validate_senderId;
        tag.validate_recipientId = validate_recipientId;
        tag.validate_aeadAlgorithm = validate_aeadAlgorithm;
        tag.validate_hkdfAlgorithm = validate_hkdfAlgorithm;
        tag.initiator={};
        tag.authenticationMethod={};
        tag.selectedCiphersuite={};
        tag.clientKeyIdentifier={};
        tag.clientPublicKey={};
        tag.privateKey={};
        tag.peerPublicKeyIdentifier={};
        tag.peerPublicKey={};
        tag.peerEdhocCoapUriPath={};
        tag.edhocOscoreCombinedSupport={};
        
        // Tag functions
        function validate_masterSecret(e){
            var str = tag.refs.masterSecret.value;
            tag.masterSecret.error = false;
            tag.masterSecret.required = false;
            tag.masterSecret.toolong = false;
            tag.masterSecret.nothexa = false;
            if (!str || 0 === str.length){
                tag.masterSecret.error = true;
                tag.masterSecret.required = true;
            }else if (str.length > 64){
                tag.masterSecret.error = true;
                tag.masterSecret.toolong = true;
            }else if (! /^[0-9a-fA-F]+$/i.test(str)){
                tag.masterSecret.error = true;
                tag.masterSecret.nothexa = true;
            }
            tag.onchange();
        }
        
        function validate_masterSalt(e){
            var str = tag.refs.masterSalt.value;
            tag.masterSalt.error = false;
            tag.masterSalt.toolong = false;
            tag.masterSalt.nothexa = false;
            var isEmpty = !str || 0 === str.length;
            if (str.length > 64){
                tag.masterSalt.error = true;
                tag.masterSalt.toolong = true;
            }else if (!isEmpty && ! /^[0-9a-fA-F]+$/i.test(str)){
                tag.masterSalt.error = true;
                tag.masterSalt.nothexa = true;
            }
            tag.onchange();
        }
        
        function validate_senderId(e){
            var str = tag.refs.senderId.value;
            tag.senderId.error = false;
            tag.senderId.toolong = false;
            tag.senderId.nothexa = false;
            var isEmpty = !str || 0 === str.length;
            if (str.length > 16){
                tag.senderId.error = true;
                tag.senderId.toolong = true;
            }else if (!isEmpty && ! /^[0-9a-fA-F]+$/i.test(str)){
                tag.senderId.error = true;
                tag.senderId.nothexa = true;
            }
            tag.onchange();
        }
        
        function validate_recipientId(e){
            var str = tag.refs.recipientId.value;
            tag.recipientId.error = false;
            tag.recipientId.toolong = false;
            tag.recipientId.nothexa = false;
            var isEmpty = !str || 0 === str.length;
            if (str.length > 16){
                tag.recipientId.error = true;
                tag.recipientId.toolong = true;
            }else if (!isEmpty && ! /^[0-9a-fA-F]+$/i.test(str)){
                tag.recipientId.error = true;
                tag.recipientId.nothexa = true;
            }
            tag.onchange();
        }
        
        function validate_aeadAlgorithm(e){
            var str = tag.refs.aeadAlgorithm.value;
            tag.aeadAlgorithm.error = false;
            tag.aeadAlgorithm.toolong = false;
            if (str.length > 32){
                tag.aeadAlgorithm.error = true;
                tag.aeadAlgorithm.toolong = true;
            }
            tag.onchange();
        }
        
        function validate_hkdfAlgorithm(e){
            var str = tag.refs.hkdfAlgorithm.value;
            tag.hkdfAlgorithm.error = false;
            tag.hkdfAlgorithm.toolong = false;
            if (str.length > 32){
                tag.hkdfAlgorithm.error = true;
                tag.hkdfAlgorithm.toolong = true;
            }
            tag.onchange();
        }

        function has_error(){
            return  typeof tag.masterSecret.error === "undefined" || tag.masterSecret.error
            || tag.masterSalt.error
            || tag.senderId.error
            || tag.recipientId.error
            || tag.aeadAlgorithm.error
            || tag.hkdfAlgorithm.error;
        }

        // Allows entering the AEAD algorithm as a string, and sets default if empty
        function parse_aeadAlgorithm(alg){

            if (!alg || 0 === alg.length){
                alg = tag.defaultAeadAlgorithm;
            }

            switch(alg) {
                case 'AES_CCM_16_64_128':
                    return 10;
                case 'AES_CCM_64_64_128':
                    return 12;
                case 'AES_CCM_16_128_128':
                    return 30;
                case 'AES_CCM_64_128_128':
                    return 32;
                default:
                    return alg;
            }
        }

        // Allows entering the HKDF algorithm as a string, and sets default if empty
        function parse_hkdfAlgorithm(alg){

            if (!alg || 0 === alg.length){
                alg = tag.defaultHkdfAlgorithm;
            }

            switch(alg) {
                case 'HKDF_HMAC_SHA_256':
                    return -10;
                default:
                    return alg;
            }
        }

        function get_value(){
            return { initiator:tag.refs.initiator.value,
                authenticationMethod:tag.refs.authenticationMethod.value,
                selectedCiphersuite:tag.refs.selectedCiphersuite.value,
                clientKeyIdentifier:tag.refs.clientKeyIdentifier.value,
                clientPublicKey:tag.refs.clientPublicKey.value,
                privateKey:tag.refs.privateKey.value,
                peerPublicKeyIdentifier:tag.refs.peerPublicKeyIdentifier.value,
                peerPublicKey:tag.refs.peerPublicKey.value,
                peerEdhocCoapUriPath:tag.refs.peerEdhocCoapUriPath.value,
                edhocOscoreCombinedSupport:tag.refs.edhocOscoreCombinedSupport.value };
        }

    </script>
</edhoc-input>

