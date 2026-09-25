// ATF step 2: ensure the filtered VIT population is large enough.
(function(outputs, steps, stepResult, assertEqual) {
    var result = new VRRiskDataHealth().run('population');
    stepResult.setOutputMessage(result.message);
    assertEqual({ name: 'VR risk health population', shouldbe: true, value: result.passed });
    return result.passed;
})(outputs, steps, stepResult, assertEqual);
