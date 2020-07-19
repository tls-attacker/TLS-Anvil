<template>
  <b-form-group
    :id="name"
    :state="state_form"
  >
    <b-form-input :type="inType" :id="name" :placeholder="' '" v-model="model" :state="state_field" trim :validated="true"></b-form-input>
    <label>{{ placeholder ? placeholder : $t(name) }}</label>

    <template v-slot:invalid-feedback><span :style="{opacity: invalid_opacity}">{{ invalid_feedback_text }}</span></template>
    <template v-slot:valid-feedback><span :style="{opacity: valid_opacity}">{{ valid_feedback_text }}</span></template>
  </b-form-group>
</template>

<script>
export default {
  name: "InputForm",
  props: {
    name: String,
    value: String,
    valFunc: {
      default: () => { return { valid: null } },
      type: Function
    },
    inType: {
      default: 'text',
      type: String
    },
    invalidFeedback: {
      default: null,
    },
    validFeedback: {
      default: null,
    },
    required: {
      default: false
    },
    placeholder: {
      default: "",
      type: String
    }
  },
  data() {
    return {
      state_form: null,
      state_field: null,
      invalid_feedback_text: "1",
      valid_feedback_text: "1",
      invalid_opacity: 1,
      valid_opacity: 1
    }
  },
  computed: {
    model: {
      get() {
        this.validate(this.value)
        return this.value
      },
      set(newValue) {
        this.$emit("input", newValue);
      }
    }
  },
  methods: {
    validate(text) {
      this.$nextTick(() => {
        if (text === "" || !text) {
          this.setup()
          this.$root.$emit("inputForm_changed", text);
          return
        }
        
        const valResult = this.validator();
        if (valResult.valid) {
          this.state_form = true
          this.state_field = this.required ? true : null
          this.valid_feedback_text = this.validFeedback ? this.validFeedback(this.model) : ""
          if (this.valid_feedback_text === "") {
            // prevents jumping around of textfields
            this.valid_feedback_text = "nothing"
            this.valid_opacity = 0
          } else {
            this.valid_opacity = 1
          }

          this.$emit("valid")
        }
        else if (valResult.valid === false) {
          this.state_form = false
          this.state_field = false
          this.invalid_feedback_text = this.invalidFeedback ? this.invalidFeedback(this.model) : this.feedback(valResult)
          if (this.invalid_feedback_text === "") {
            // prevents jumping around of textfields
            this.invalid_feedback_text = "nothing"
            this.invalid_opacity = 0
          } else {
            this.invalid_opacity = 1
          }
        }
        else {
          this.state_form = true
          this.state_field = null
          this.invalid_opacity = 0
          this.valid_opacity = 0
          this.valid_feedback_text = "nothing"
        }

        this.$root.$emit("inputForm_changed", text);
      })
    },
    validator() {
      return this.valFunc(this.model, this.name);
    },
    feedback(valResult) {
      if (valResult.err && valResult.err.message !== "") {
        return this.$t("backend.formValidation." + valResult.err.message);
      }
      return "";
    },
    setup() {
      if (this.model !== "" && this.model != undefined) {
        this.validate(this.model)
        return
      }
      
      if (this.required && this.valFunc) {
        this.state_form = false
        this.state_field = null
        this.invalid_feedback_text = this.$t("general.required")
        this.invalid_opacity = 1
      }
      else {
        this.state_form = true
        this.state_field = null
        this.valid_feedback_text = "nothing"
        this.valid_opacity = 0
      }
    }
  },
  mounted() {
    this.setup();
  }
};
</script>
<style lang="scss" scoped>

.form-group {
  position: relative;
}

.form-group input,
.form-group label {
  padding: 16px;
}

.form-group input {
  height: 48px
}

.form-group label {
  position: absolute;
  top: -3px;
  left: 0;
  width: 100%;
  margin-bottom: 0; /* Override default `<label>` margin */
  color: #495057;
  border: 1px solid transparent;
  border-radius: 8px;
  transition: all .1s ease-in-out;
  font-size: 1.25rem;
  font-weight: 400;
  line-height: 1;
  pointer-events: none;
}

.form-group input::-webkit-input-placeholder {
  color: transparent;
}

.form-group input:-ms-input-placeholder {
  color: transparent;
}

.form-group input::-ms-input-placeholder {
  color: transparent;
}

.form-group input::-moz-placeholder {
  color: transparent;
}

.form-group input::placeholder {
  color: transparent;
}

.form-group input:not(:placeholder-shown) {
  padding-top: 20px;
  padding-bottom: 4px;

  &.is-invalid, &.is-valid {
    padding-right: 34px;
  }
}

.form-group input:not(:-ms-input-placeholder) {
  padding-top: 20px;
  padding-bottom: 4px;

  &.is-invalid, &.is-valid {
    padding-right: 34px;
  }
}

.form-group input:not(:placeholder-shown) ~ label {
  padding-top: 10px;
  padding-bottom: 4px;
  font-size: 12px;
  color: #777;
}

.form-group input:not(:-ms-input-placeholder) ~ label {
  padding-top: 10px;
  padding-bottom: 4px;
  font-size: 12px;
  color: #777;
}
</style>
