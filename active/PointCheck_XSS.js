// TODO: add base reflect check.
// TODO: add form data to post test.
alertRisk = 3; alertReliability = 3; alertCWE_ID = 0; alertWASC_ID = 0;

alertTitle		= "Point XSS";
alertParam		= "N/A";
alertAttack		= "__point_check__<';\"scRsCriPtIpt";
alertEvidence	= "Reference to Description";
alertDesc		= "XSS Injection string test.";
alertOtherInfo	= "";
alertSolution	= "filter a script string.";

function scan(as, msg, param, value) {
	if (!checkReflect(as, msg, param)) return;

	as.setParam(msg, param, alertAttack);	// setParam (message, parameterName, newValue)
	as.sendAndReceive(msg, false, false);	// sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)

	var re = /__point_check__(?:[<'"&glt;%3c27]*)?(?:[script]*)?/gi;
	var body = msg.getResponseBody().toString();
	var alertParam = param;

	var foundResults = [];
	var counter = 0;

	while(comm = re.exec(body)) {
		counter = counter + 1;
		foundResults.push(comm[0]+"\n");
	}

	if (counter > 0) {
		alertOtherInfo = foundResults.toString();
		as.raiseAlert(alertRisk, alertReliability, alertTitle, alertDesc,
			msg.getRequestHeader().getURI().toString(), alertParam, alertAttack,
			alertOtherInfo, alertSolution, alertEvidence, alertCWE_ID, alertWASC_ID, msg);
	} else {
		alertOtherInfo = foundResults.toString();
		as.raiseAlert(alertRisk-1, alertReliability, alertTitle + " just reflect", alertDesc,
			msg.getRequestHeader().getURI().toString(), alertParam, "__point_check__",
			"__point_check__", alertSolution, alertEvidence, alertCWE_ID, alertWASC_ID, msg);
	}
}

function checkReflect(as, msg, param) {
	as.setParam(msg, param, "__point_check__");	// setParam (message, parameterName, newValue)
	as.sendAndReceive(msg, false, false);	// sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)

	var re = /__point_check__/gi;
	var body = msg.getResponseBody().toString();
	if (re.exec(body)) return true;
	else return false;
}