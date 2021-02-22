<template>
  <div id="app">
    <b-navbar toggleable="md" type="dark" variant="secondary">
      <b-navbar-brand href="#">TestReport Analyzer</b-navbar-brand>

      <b-navbar-toggle target="nav-collapse"></b-navbar-toggle>

      <b-collapse id="nav-collapse" is-nav>
        <b-navbar-nav>
          <b-nav-item href="#/">Upload</b-nav-item>
          <b-nav-item href="#/analyzer">Analyzer</b-nav-item>
          <b-nav-item href="#/manage">Manage</b-nav-item>
        </b-navbar-nav>

      </b-collapse>
    </b-navbar>
    <div id="container">
      <keep-alive>
        <router-view />
      </keep-alive>
    </div>
  </div>
</template>

<style lang="scss">
@import "../node_modules/bootstrap/scss/bootstrap";
@import "../node_modules/bootstrap-vue/src/index.scss";

#app {
  font-family: Avenir, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  color: #2c3e50;
}

#container {
  padding: 30px 20px 0 20px;
}

h1 {
  margin-bottom: 20px;
}

.btn {
  margin-right: 10px;
}

.selectable {
  cursor: pointer;
}
</style>
