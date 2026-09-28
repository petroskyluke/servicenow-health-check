// ATF step 2: check both population bounds and percentage count tolerance.
(function(outputs, steps, stepResult, assertEqual) {
    var result = new sn_vul.VRRiskDataHealth().run('population');
    stepResult.setOutputMessage(result.message);
    assertEqual({ name: 'VR risk health population', shouldbe: true, value: result.passed });
    return result.passed;
})(outputs, steps, stepResult, assertEqual);
