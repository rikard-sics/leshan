<edhoc-input>
    <!-- EDHOC inputs -->
    <div class={ form-group:true }>
        <label for="initiator" class="col-sm-4 control-label">Initiator</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="2" id="initiator" ref="initiator"></textarea>
        </div>
    </div>
    
    <div class={ form-group:true }>
        <label for="authenticationMethod" class="col-sm-4 control-label">Authentication Method</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="2" id="authenticationMethod" ref="authenticationMethod"></textarea>
        </div>
    </div>

    <div class={ form-group:true }>
        <label for="ciphersuite" class="col-sm-4 control-label">Ciphersuite</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="2" id="ciphersuite" ref="ciphersuite"></textarea>
            <p class="text-right text-muted small" style="margin:0">Hexadecimal format</p>
        </div>
    </div>

    <div class={ form-group:true }>
        <label for="credentialIdentifier" class="col-sm-4 control-label">Credential Identifier</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="2" id="credentialIdentifier" ref="credentialIdentifier"></textarea>
            <p class="text-right text-muted small" style="margin:0">Hexadecimal format</p>
        </div>
    </div>

    <div class={ form-group:true }>
        <label for="publicCredential" class="col-sm-4 control-label">Public Credential</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="2" id="publicCredential" ref="publicCredential"></textarea>
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
            <textarea class="form-control" style="resize:none" rows="2" id="serverCredentialIdentifier" ref="serverCredentialIdentifier"></textarea>
            <p class="text-right text-muted small" style="margin:0">Hexadecimal format</p>
        </div>
    </div>

    <div class={ form-group:true }>
        <label for="serverPublicKey" class="col-sm-4 control-label">Server Public Key</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="2" id="serverPublicKey" ref="serverPublicKey"></textarea>
            <p class="text-right text-muted small" style="margin:0">Hexadecimal format</p>
        </div>
    </div>

    <div class={ form-group:true }>
        <label for="oscoreMasterSecretLength" class="col-sm-4 control-label">OSCORE Master Secret Length</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="2" id="oscoreMasterSecretLength" ref="oscoreMasterSecretLength"></textarea>
        </div>
    </div>

    <div class={ form-group:true }>
        <label for="oscoreMasterSaltLength" class="col-sm-4 control-label">OSCORE Master Salt Length</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="2" id="oscoreMasterSaltLength" ref="oscoreMasterSaltLength"></textarea>
        </div>
    </div>

    <div class={ form-group:true }>
        <label for="edhocOscoreCombined" class="col-sm-4 control-label">EDHOC OSCORE Combined</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="2" id="edhocOscoreCombined" ref="edhocOscoreCombined"></textarea>
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
