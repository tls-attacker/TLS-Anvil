<template>
  <div class="container">
    <div v-for="(container, containerIdx) in filter" :key="containerIdx">
      <div class="conditionContainer">
        <b-row
          v-for="(condition, conditionIdx) in container.conditions"
          :key="conditionIdx"
          class="condition"
        >
          <b-col>
            <b-form-select
              v-model="condition.key"
              :options="keys"
              @change="keyChanged(condition)"
            ></b-form-select>
          </b-col>
          <b-col cols="2">
            <template v-if="condition.key && hasMultipleComparators(condition.key)">
              <b-form-select
                v-model="condition.comparator"
                :options="propertiesForKey(condition.key).comparators"
              ></b-form-select>
            </template>
            <template v-else-if="condition.key">
              <span class="comparatorText">{{
                propertiesForKey(condition.key).comparators
              }}</span>
            </template>
          </b-col>
          <b-col>
            <template v-if="condition.key && (propertiesForKey(condition.key).type === 'text' || condition.comparator.indexOf('contains') > -1)">
              <b-form-input
                placeholder="Value"
                autocomplete="false"
                debounce="500"
                v-model="condition.value"
                :list="JSON.stringify(condition.key) + containerIdx.toString() + conditionIdx.toString()"
              ></b-form-input>
              <b-form-datalist :id="JSON.stringify(condition.key) + containerIdx.toString() + conditionIdx.toString()" :options="propertiesForKey(condition.key).values"></b-form-datalist>
            </template>
            <template
              v-else-if="
                condition.key &&
                propertiesForKey(condition.key).type === 'selector'
              "
            >
              <b-form-select
                v-model="condition.value"
                :options="propertiesForKey(condition.key).values"
              ></b-form-select>
            </template>
          </b-col>
          <b-col cols="2">
            <b-button
              @click="addCondition($event, containerIdx, conditionIdx)"
              v-bind="condition.addBtnStyle"
              class="addBtn"
              v-text="btnTextForOperator(condition.operator)"
              :disabled="!condition.key"
            ></b-button>
            <b-icon
              style="cursor: pointer"
              v-if="condition.operator != 'ADD'"
              @click="removeCondition(containerIdx, conditionIdx)"
              icon="trash"
              variant="danger"
            ></b-icon>
          </b-col>
        </b-row>
      </div>

      <div style="display: flex; justify-content: center; align-items: center">
        <b-button
          style="margin-top: -12px; width: 45px"
          v-bind="container.addBtnStyle"
          v-text="btnTextForOperator(container.operator)"
          @click="addContainer($event, containerIdx)"
        ></b-button>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: "TableFilter",
  model: {
    prop: 'filter',
    event: 'change'
  },
  props: {
    filterPossibilities: {
      type: Array,
      required: true
    },
    filter: {
      type: Array,
      required: true
    }
  },

  data() {
    return {
      
    };
  },

  computed: {
    keys() {
      return [
        { value: null, text: "Key" },
        ...this.filterPossibilities.map((i) => {
          return { value: {type: i.key.type, mode: i.key.mode}, text: i.displayName };
        }),
      ];
    },
  },

  mounted() {
    if (this.filter.length == 0) {
      this.filter.push(this.createBaseContainer());
    }
  },

  methods: {
    propertiesForKey(key) {
      return this.filterPossibilities.filter((i) => {
        return key.mode === i.key.mode && key.type === i.key.type;
      })[0];
    },

    hasMultipleComparators(key) {
      return !(typeof this.propertiesForKey(key).comparators === "string");
    },

    btnTextForOperator(operator) {
      switch (operator) {
        case "AND":
          return "&&";
        case "OR":
          return "||";
        case "ADD":
          return "Add";
      }
    },

    createBaseContainer() {
      return {
        operator: "ADD",
        conditions: [this.createBaseCondition()],
        addBtnStyle: {
          variant: "primary",
          pill: true,
          size: "sm",
        },
      };
    },

    createBaseCondition() {
      return {
        key: null,
        value: null,
        comparator: null,
        operator: "ADD",
        addBtnStyle: {
          variant: "primary",
          pill: false,
          size: "md",
        },
      };
    },

    addContainer(event, containerIdx) {
      const target = event.target;
      const container = this.filter[containerIdx];

      if (container.operator == "ADD") {
        this.filter.push(this.createBaseContainer());
        container.addBtnStyle.variant = "success";
        container.operator = "AND";
      } else if (container.operator == "AND") {
        container.addBtnStyle.variant = "warning";
        container.operator = "OR";
      } else if (container.operator == "OR") {
        container.addBtnStyle.variant = "success";
        container.operator = "AND";
      }

      target.innerText = this.btnTextForOperator(container.operator);
    },

    addCondition(event, containerIdx, conditionIdx) {
      const target = event.target;
      const condition = this.filter[containerIdx].conditions[conditionIdx];
      if (condition.operator == "ADD") {
        this.filter[containerIdx].conditions.push(this.createBaseCondition());
        condition.operator = "AND";
        condition.addBtnStyle.variant = "success";
        condition.addBtnStyle.pill = true;
        condition.addBtnStyle.size = "sm";
      } else if (condition.operator === "AND") {
        condition.operator = "OR";
        condition.addBtnStyle.variant = "warning";
      } else if (condition.operator === "OR") {
        condition.operator = "AND";
        condition.addBtnStyle.variant = "success";
      }

      target.innerText = this.btnTextForOperator(condition.operator);
    },

    removeCondition(containerIdx, conditionIdx) {
      this.filter[containerIdx].conditions.splice(conditionIdx, 1);
    },

    keyChanged(condition) {
      if (!condition.key) {
        condition.comparator = null;
        condition.value = null;
        return;
      }

      if (this.hasMultipleComparators(condition.key)) {
        condition.comparator = this.propertiesForKey(
          condition.key
        ).comparators[0];
      } else {
        condition.comparator = this.propertiesForKey(condition.key).comparators;
      }

      condition.value = this.propertiesForKey(condition.key).values[0]
      if (typeof condition.value != 'string') {
        condition.value = condition.value.value
      }
    },
  },
};
</script>


<style lang="scss" scoped>
.container {
  margin-top: 40px
}

.condition {
  margin-bottom: 15px;
}

.conditionContainer {
  background-color: #ddd;
  padding: 20px 20px 5px 20px;
  border-radius: 10px;
  margin-top: -10px;
}

.comparatorText {
  line-height: 38px;
}

.addBtn {
  width: 60px;
}
</style>
