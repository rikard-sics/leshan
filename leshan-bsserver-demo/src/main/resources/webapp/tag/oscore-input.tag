<oscore-input>
    <!-- OSCORE inputs -->
    <div class={ form-group:true, has-error: oscoreId.error }>
        <label for="oscoreId" class="col-sm-4 control-label">OSCORE Identity</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="3" id="oscoreId" ref="oscoreId" oninput={validate_oscoreId} onblur={validate_oscoreId}></textarea>
            <p class="help-block" if={oscoreId.required} >The OSCORE identity is required</p>
            <p class="help-block" if={oscoreId.toolong} >The OSCORE identity is too long</p>
        </div>
    </div>

    <div class={ form-group:true, has-error: oscoreVal.error }>
        <label for="oscoreVal" class="col-sm-4 control-label">Key</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="3" id="oscoreVal" ref="oscoreVal" oninput={validate_oscoreVal} onblur={validate_oscoreVal}></textarea>
            <p class="text-right text-muted small" style="margin:0">Hexadecimal format</p>
            <p class="help-block" if={oscoreVal.required}>The pre-shared key is required</p>
            <p class="help-block" if={oscoreVal.nothexa}>Hexadecimal format is expected</p>
            <p class="help-block" if={oscoreVal.toolong}>The pre-shared key is too long</p>
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
        // Tag intenal state
        tag.oscoreId={};
        tag.oscoreVal={};
        tag.validate_oscoreId = validate_oscoreId;
        tag.validate_oscoreVal = validate_oscoreVal;

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

        function has_error(){
            return  typeof tag.oscoreId.error === "undefined" || tag.oscoreId.error || typeof tag.oscoreVal.error === "undefined" || tag.oscoreVal.error;
        }

        function get_value(){
            return { id:tag.refs.oscoreId.value, key:tag.refs.oscoreVal.value };
        }
    </script>
</oscore-input>

