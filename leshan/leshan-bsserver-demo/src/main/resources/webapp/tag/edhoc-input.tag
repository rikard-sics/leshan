<edhoc-input>
    <!-- EDHOC inputs -->
    
    <!-- TODO: Add validation -->
    
    <div class={ form-group:true }>
        <label for="initiator" class="col-sm-4 control-label">Initiator</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="1" id="initiator" ref="initiator"></textarea>
        </div>
    </div>
    
    <div class={ form-group:true }>
        <label for="authenticationMethod" class="col-sm-4 control-label">Authentication Method</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="1" id="authenticationMethod" ref="authenticationMethod"></textarea>
        </div>
    </div>

    <div class={ form-group:true }>
        <label for="ciphersuite" class="col-sm-4 control-label">Ciphersuite</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="1" id="ciphersuite" ref="ciphersuite"></textarea>
        </div>
    </div>

    <div class={ form-group:true }>
        <label for="credentialIdentifier" class="col-sm-4 control-label">Credential Identifier</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="1" id="credentialIdentifier" ref="credentialIdentifier"></textarea>
            <p class="text-right text-muted small" style="margin:0">Hexadecimal format</p>
        </div>
    </div>

    <div class={ form-group:true }>
        <label for="publicCredential" class="col-sm-4 control-label">Public Credential</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="4" id="publicCredential" ref="publicCredential"></textarea>
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
        <label for="serverCredentialIdentifier" class="col-sm-4 control-label">Server Credential Identifier</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="1" id="serverCredentialIdentifier" ref="serverCredentialIdentifier"></textarea>
            <p class="text-right text-muted small" style="margin:0">Hexadecimal format</p>
        </div>
    </div>

    <div class={ form-group:true }>
        <label for="serverPublicKey" class="col-sm-4 control-label">Server Public Credential</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="4" id="serverPublicKey" ref="serverPublicKey"></textarea>
            <p class="text-right text-muted small" style="margin:0">Hexadecimal format</p>
        </div>
    </div>

    <div class={ form-group:true }>
        <label for="oscoreMasterSecretLength" class="col-sm-4 control-label">OSCORE Master Secret Length</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="1" id="oscoreMasterSecretLength" ref="oscoreMasterSecretLength"></textarea>
        </div>
    </div>

    <div class={ form-group:true }>
        <label for="oscoreMasterSaltLength" class="col-sm-4 control-label">OSCORE Master Salt Length</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="1" id="oscoreMasterSaltLength" ref="oscoreMasterSaltLength"></textarea>
        </div>
    </div>

    <div class={ form-group:true }>
        <label for="edhocOscoreCombined" class="col-sm-4 control-label">EDHOC OSCORE Combined</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="1" id="edhocOscoreCombined" ref="edhocOscoreCombined"></textarea>
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
        tag.ciphersuite={};
        tag.credentialIdentifier={};
        tag.publicCredential={};
        tag.privateKey={};
        tag.serverCredentialIdentifier={};
        tag.serverPublicKey={};
        tag.oscoreMasterSecretLength={};
        tag.oscoreMasterSaltLength={};
        tag.edhocOscoreCombined={};
        
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
                ciphersuite:tag.refs.ciphersuite.value,
                credentialIdentifier:tag.refs.credentialIdentifier.value,
                publicCredential:tag.refs.publicCredential.value,
                privateKey:tag.refs.privateKey.value,
                serverCredentialIdentifier:tag.refs.serverCredentialIdentifier.value,
                serverPublicKey:tag.refs.serverPublicKey.value,
                oscoreMasterSecretLength:tag.refs.oscoreMasterSecretLength.value,
                oscoreMasterSaltLength:tag.refs.oscoreMasterSaltLength.value,
                edhocOscoreCombined:tag.refs.edhocOscoreCombined.value };
        }
    </script>
</edhoc-input>

