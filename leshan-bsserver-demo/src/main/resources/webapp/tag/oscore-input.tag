<oscore-input>
    <!-- OSCORE inputs -->
    <div class={ form-group:true, has-error: oscoreId.error }>
        <label for="oscoreId" class="col-sm-4 control-label">OSCORE Identity</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="2" id="oscoreId" ref="oscoreId" oninput={validate_oscoreId} onblur={validate_oscoreId}></textarea>
            <p class="help-block" if={oscoreId.required} >The OSCORE identity is required</p>
            <p class="help-block" if={oscoreId.toolong} >The OSCORE identity is too long</p>
        </div>
    </div>

    <div class={ form-group:true, has-error: oscoreVal.error }>
        <label for="oscoreVal" class="col-sm-4 control-label">Key</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="2" id="oscoreVal" ref="oscoreVal" oninput={validate_oscoreVal} onblur={validate_oscoreVal}></textarea>
            <p class="text-right text-muted small" style="margin:0">Hexadecimal format</p>
            <p class="help-block" if={oscoreVal.required}>The pre-shared key is required</p>
            <p class="help-block" if={oscoreVal.nothexa}>Hexadecimal format is expected</p>
            <p class="help-block" if={oscoreVal.toolong}>The pre-shared key is too long</p>
        </div>
    </div>
    
    <div class={ form-group:true, has-error: masterSecret.error }>
        <label for="masterSecret" class="col-sm-4 control-label">Master Secret</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="2" id="masterSecret" ref="masterSecret" oninput={validate_masterSecret} onblur={validate_masterSecret}></textarea>
            <p class="text-right text-muted small" style="margin:0">Hexadecimal format</p>
            <p class="help-block" if={masterSecret.required}>The master secret is required</p>
            <p class="help-block" if={masterSecret.nothexa}>Hexadecimal format is expected</p>
            <p class="help-block" if={masterSecret.toolong}>The master secret is too long</p>
        </div>
    </div>
    
    <div class={ form-group:true, has-error: masterSalt.error }>
        <label for="masterSalt" class="col-sm-4 control-label">Master Salt</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="2" id="masterSalt" ref="masterSalt" oninput={validate_masterSalt} onblur={validate_masterSalt}></textarea>
            <p class="text-right text-muted small" style="margin:0">Hexadecimal format</p>
            <p class="help-block" if={masterSalt.nothexa}>Hexadecimal format is expected</p>
            <p class="help-block" if={masterSalt.toolong}>The master salt is too long</p>
        </div>
    </div>
    
    <div class={ form-group:true, has-error: idContext.error }>
        <label for="idContext" class="col-sm-4 control-label">ID Context</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="1" id="idContext" ref="idContext" oninput={validate_idContext} onblur={validate_idContext}></textarea>
            <p class="text-right text-muted small" style="margin:0">Hexadecimal format</p>
            <p class="help-block" if={idContext.nothexa}>Hexadecimal format is expected</p>
            <p class="help-block" if={idContext.toolong}>The ID context is too long</p>
        </div>
    </div>
    
    <div class={ form-group:true, has-error: senderId.error }>
        <label for="senderId" class="col-sm-4 control-label">Sender ID</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="1" id="senderId" ref="senderId" oninput={validate_senderId} onblur={validate_senderId}></textarea>
            <p class="text-right text-muted small" style="margin:0">Hexadecimal format</p>
            <p class="help-block" if={senderId.nothexa}>Hexadecimal format is expected</p>
            <p class="help-block" if={senderId.toolong}>The sender ID is too long</p>
        </div>
    </div>

    <div class={ form-group:true, has-error: recipientId.error }>
        <label for="recipientId" class="col-sm-4 control-label">Recipient ID</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="1" id="recipientId" ref="recipientId" oninput={validate_recipientId} onblur={validate_recipientId}></textarea>
            <p class="text-right text-muted small" style="margin:0">Hexadecimal format</p>
            <p class="help-block" if={recipientId.nothexa}>Hexadecimal format is expected</p>
            <p class="help-block" if={recipientId.toolong}>The recipient ID is too long</p>
        </div>
    </div>
    
    <div class={ form-group:true, has-error: aeadAlgorithm.error }>
        <label for="aeadAlgorithm" class="col-sm-4 control-label">AEAD Algorithm</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="1" id="aeadAlgorithm" ref="aeadAlgorithm" oninput={validate_aeadAlgorithm} onblur={validate_aeadAlgorithm} placeholder={defaultAeadAlgorithm}></textarea>
            <p class="help-block" if={aeadAlgorithm.toolong}>The AEAD algorithm is too long</p>
        </div>
    </div>
    
    <div class={ form-group:true, has-error: hkdfAlgorithm.error }>
        <label for="hkdfAlgorithm" class="col-sm-4 control-label">HKDF Algorithm</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="1" id="hkdfAlgorithm" ref="hkdfAlgorithm" oninput={validate_hkdfAlgorithm} onblur={validate_hkdfAlgorithm} placeholder={defaultHkdfAlgorithm}></textarea>
            <p class="help-block" if={hkdfAlgorithm.toolong}>The HKDF algorithm is too long</p>
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
        tag.oscoreId={};
        tag.oscoreVal={};
        tag.masterSecret={};
        tag.masterSalt={};
        tag.idContext={};
        tag.senderId={};
        tag.recipientId={};
        tag.aeadAlgorithm={};
        tag.defaultAeadAlgorithm = "AES_CCM_16_64_128"
        tag.hkdfAlgorithm={};
        tag.defaultHkdfAlgorithm = "HKDF_HMAC_SHA_256"
        tag.validate_oscoreId = validate_oscoreId;
        tag.validate_oscoreVal = validate_oscoreVal;
        tag.validate_masterSecret = validate_masterSecret;
        tag.validate_masterSalt = validate_masterSalt;
        tag.validate_idContext = validate_idContext;
        tag.validate_senderId = validate_senderId;
        tag.validate_recipientId = validate_recipientId;
        tag.validate_aeadAlgorithm = validate_aeadAlgorithm;
        tag.validate_hkdfAlgorithm = validate_hkdfAlgorithm;

        // Tag functions
        function validate_oscoreId(e){
            var str = tag.refs.oscoreId.value; 
            tag.oscoreId.error = false;
            tag.oscoreId.required = false;
            tag.oscoreId.toolong = false;
            if (!str || 0 === str.length){
                tag.oscoreId.error = true;
                tag.oscoreId.required = true;
            }else if (str.length > 128){
                tag.oscoreId.error = true;
                tag.oscoreId.toolong = true;
            }
            tag.onchange();
        }

        function validate_oscoreVal(e){
            var str = tag.refs.oscoreVal.value;
            tag.oscoreVal.error = false;
            tag.oscoreVal.required = false;
            tag.oscoreVal.toolong = false;
            tag.oscoreVal.nothexa = false;
            if (!str || 0 === str.length){
                tag.oscoreVal.error = true;
                tag.oscoreVal.required = true;
            }else if (str.length > 128){
                tag.oscoreVal.error = true;
                tag.oscoreVal.toolong = true;
            }else if (! /^[0-9a-fA-F]+$/i.test(str)){
                tag.oscoreVal.error = true;
                tag.oscoreVal.nothexa = true;
            }
            tag.onchange();
        }
        
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
            if (str.length > 64){
                tag.masterSalt.error = true;
                tag.masterSalt.toolong = true;
            }else if (! /^[0-9a-fA-F]+$/i.test(str)){
                tag.masterSalt.error = true;
                tag.masterSalt.nothexa = true;
            }
            tag.onchange();
        }
        
        function validate_idContext(e){
            var str = tag.refs.idContext.value;
            tag.idContext.error = false;
            tag.idContext.toolong = false;
            tag.idContext.nothexa = false;
            if (str.length > 32){
                tag.idContext.error = true;
                tag.idContext.toolong = true;
            }else if (! /^[0-9a-fA-F]+$/i.test(str)){
                tag.idContext.error = true;
                tag.idContext.nothexa = true;
            }
            tag.onchange();
        }
        
        function validate_senderId(e){
            var str = tag.refs.senderId.value;
            tag.senderId.error = false;
            tag.senderId.toolong = false;
            tag.senderId.nothexa = false;
            if (str.length > 16){
                tag.senderId.error = true;
                tag.senderId.toolong = true;
            }else if (! /^[0-9a-fA-F]+$/i.test(str)){
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
            if (str.length > 16){
                tag.recipientId.error = true;
                tag.recipientId.toolong = true;
            }else if (! /^[0-9a-fA-F]+$/i.test(str)){
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
            return  typeof tag.oscoreId.error === "undefined" || tag.oscoreId.error || typeof tag.oscoreVal.error === "undefined" || tag.oscoreVal.error
            || typeof tag.masterSecret.error === "undefined" || tag.masterSecret.error
            || typeof tag.masterSalt.error === "undefined" || tag.masterSalt.error
            || typeof tag.idContext.error === "undefined" || tag.idContext.error
            || typeof tag.senderId.error === "undefined" || tag.senderId.error
            || typeof tag.recipientId.error === "undefined" || tag.recipientId.error
            || tag.aeadAlgorithm.error
            || tag.hkdfAlgorithm.error;
        }

        function get_value(){
            return { id:tag.refs.oscoreId.value, key:tag.refs.oscoreVal.value,
            	masterSecret:tag.refs.masterSecret.value,
            	masterSalt:tag.refs.masterSalt.value,
            	idContext:tag.refs.idContext.value,
            	senderId:tag.refs.senderId.value,
            	recipientId:tag.refs.recipientId.value,
            	aeadAlgorithm:tag.refs.aeadAlgorithm.value,
            	hkdfAlgorithm:tag.refs.hkdfAlgorithm.value };
        }
    </script>
</oscore-input>

