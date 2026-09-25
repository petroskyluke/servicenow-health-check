// ATF step 1: validate configuration and required fields.
(function(outputs, steps, stepResult, assertEqual) {
    var result = new VRRiskDataHealth().run('configuration');
    stepResult.setOutputMessage(result.message);
    assertEqual({ name: 'VR risk health configuration', shouldbe: true, value: result.passed });
    return result.passed;
})(outputs, steps, stepResult, assertEqual);
