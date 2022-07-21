<template>
  <div>
    <b-form>
      <div class="valid-feedback"></div>
      <b-form-group 
        label="Title of the edit"
        :state="!!data.title"
        invalid-feedback="Required"
        valid-feedback="Ok"
      >
        <b-form-input 
          v-model="data.title" 
          placeholder="Title"
          :state="!!data.title"
          @input="updateValue('title', $event)"
        ></b-form-input>
      </b-form-group>


      <b-form-group 
        label="Which test reports should be affected by the editing?"
        :state="!!data.editMode"
        invalid-feedback="Required"
        valid-feedback="Ok"
      >
        <b-form-radio-group
          v-model="data.editMode"
          @change="changedMode($event); updateValue('editMode', $event)"
          :options="modeOptions"
          name="mode-radios"
          stacked
          :state="!!data.editMode"
        ></b-form-radio-group>

        <template v-if="data.editMode == editMode.specified">
          <b-form-select 
            v-model="data.identifiers" 
            @change="updateValue('identifiers',  $event)"
            :options="allIdentifiers" 
            multiple 
            :select-size="6"
          ></b-form-select>
        </template>
      </b-form-group>

      <b-form-group 
        label="Change the overall test result to:"
        :state="!!data.newResult"
        invalid-feedback="Required"
        valid-feedback="Ok"
      >
        <b-form-radio-group
          v-model="data.newResult"
          @change="updateValue('newResult',  $event)"
          :options="resultOptions"
          name="result-radios"
          stacked
          :state="!!data.newResult"
        ></b-form-radio-group>
      </b-form-group>

      <b-form-group 
        label="Describe the edit:"
        invalid-feedback="Required"
        valid-feedback="Ok"
        :state="!!data.description"
      >
        <b-form-textarea
          id="textarea"
          v-model="data.description"
          @input="updateValue('description',  $event)"
          placeholder="Enter a description..."
          rows="3"
          max-rows="6"
          :state="!!data.description"
        ></b-form-textarea>
      </b-form-group>

      <template v-if="data.identifiers">
        <p>
          This edit will affect the following reports:<br>
          <ul>
            <li v-for="k in data.identifiers" :key="k">{{k}}</li>
          </ul>
        </p>
        
      </template>
      
    </b-form>
  </div>  
</template>

<script>
import { TestResult, EditMode } from '@/lib/const'

export default {
  props: {
    value: Object
  },
  model: {
    prop: 'value',
    event: 'input'
  },
  data() {
    return {
      modeOptions: [
        { text: "Selected Reports", value: EditMode.selected},
        { text: "All available Reports", value: EditMode.allAvailable},
        { text: "All Reports (available + uploaded in the future)", value: EditMode.allAll},
        { text: "Specified", value: EditMode.specified},
      ],
      resultOptions: [
        { text: "Disabled", value: TestResult.DISABLED},
        { text: "Strictly Succeeded", value: TestResult.STRICTLY_SUCCEEDED},
        { text: "Conceptually Succeeded", value: TestResult.CONCEPTUALLY_SUCCEEDED},
        { text: "Partially Failed", value: TestResult.PARTIALLY_FAILED},
        { text: "Fully Failed", value: TestResult.FULLY_FAILED},
      ]
    }
  },
  computed: {
    data() {
      return this.value
    },

    editMode() {
      return EditMode
    },

    validated() {
      return !!this.data.description && !!this.data.newResult && !!this.data.editMode
    },

    allIdentifiers() {
      return this.$store.state.allIdentifiers
    },

    selectedIdentifiers() {
      return this.$store.state.selectedIdentifiers
    }
  },
  watch: {
    validated(newValue) {
      this.data.validated = newValue
      this.updateValue('validated',  newValue)
    }
  },
  methods: {
    changedMode(mode) {
      if (mode === EditMode.selected || mode === EditMode.specified) {
        this.data.identifiers = this.selectedIdentifiers
      } else if (mode == EditMode.allAvailable) {
        this.data.identifiers = this.allIdentifiers
      } else {
        this.data.identifiers = ["Reports uploaded in the future", ...this.allIdentifiers]
      }
    },

    updateValue(key, value) {
      console.log(value)
      this.$emit("input", { ...this.data, [key]: value });
    }
  }
}
</script>

<style lang="scss">
.valid-feedback {
  opacity: 0 !important;
}
</style>