alertRisk = 3; alertReliability = 3; alertCWE_ID = 0; alertWASC_ID = 0;

alertTitle		= "Point SQL Injection";
alertParam		= "N/A";
alertAttack		= "";
alertEvidence	= "Reference to Other Info";

alertDesc		= "SQL Injection string test.";
alertOtherInfo	= "";
alertSolution	= "erase";

function scan(as, msg, param, value) {
	var hasProblem = false;
	alertParam = param + "=" + value;
	msgOriginal = msg.cloneRequest();
	magModified = msg.cloneRequest();

	var number = parseInt(value);
	var attackValues = [];

	var replaceIndex = value.indexOf("=");
	replaceIndex = replaceIndex == -1 ? value.length/2 : replaceIndex + ((value.length - replaceIndex)/2)

	if (isNaN(number)) {
		if (value.length > 2) {
			attackValues.push(value.substring(0,replaceIndex) + "'||'" + value.substring(replaceIndex, value.length));
			attackValues.push(value.substring(0,replaceIndex) + "'+'" + value.substring(replaceIndex, value.length));
			attackValues.push(value.substring(0,replaceIndex) + "' '" + value.substring(replaceIndex, value.length));
			attackValues.push(value.substring(0,replaceIndex) + "'%09'" + value.substring(replaceIndex, value.length));
			attackValues.push(value.substring(0,replaceIndex) + "'/**/'" + value.substring(replaceIndex, value.length));
			attackValues.push(value + "`#");
			attackValues.push(value + "`--");
		}
	} else {
		attackValues.push((number + 1) + "-1");
		attackValues.push((number + 1) + "\n-1");
	}

	as.sendAndReceive(msgOriginal, false, false);
	var bodyOriginal	= msgOriginal.getResponseBody().toString();
	var statusOriginal	= msgOriginal.getResponseHeader().getStatusCode();

	var bodyOriginalForDiff = bodyOriginal.replaceAll(value, "");
	for (var j=0; j < attackValues.length; j++) {
		
		as.setParam(magModified, param, attackValues[j]);
		as.sendAndReceive(magModified, false, false);

		var bodyModified	= magModified.getResponseBody().toString();
		var statusModified	= magModified.getResponseHeader().getStatusCode();

		var bodyModifiedForDiff = bodyModified.replaceAll(value, "");
		bodyModifiedForDiff = bodyModifiedForDiff.replaceAll(attackValues[j], "");

		if (bodyOriginalForDiff == bodyModifiedForDiff) {
			alertDesc = "It's possible";
			alertAttack += attackValues[j] + ", ";
			alertOtherInfo += "original: " + value + " >>> modified: " + attackValues[j] + "\n";
			hasProblem = true;
		} else if(statusOriginal != statusModified) {
			alertDesc = "Status Code is not same.\n";
			alertAttack += attackValues[j] + ", ";
			alertOtherInfo += "original: " + statusOriginal + " >>> modified: " + statusModified + "\n";
			hasProblem = true;
		}
	}

	if(hasProblem)
		as.raiseAlert(alertRisk, alertReliability, alertTitle, alertDesc,
			msg.getRequestHeader().getURI().toString(), alertParam, alertAttack,
			alertOtherInfo, alertSolution, alertEvidence, alertCWE_ID, alertWASC_ID, msg);
}

String.prototype.replaceAll = function(str1, str2, ignore) {
    return this.replace(new RegExp(str1.replace(/([\/\,\!\\\^\$\{\}\[\]\(\)\.\*\+\?\|\<\>\-\&])/g,"\\$&"),(ignore?"gi":"g")),(typeof(str2)=="string")?str2.replace(/\$/g,"$$$$"):str2);
}