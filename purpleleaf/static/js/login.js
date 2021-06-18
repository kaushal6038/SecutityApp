$(document).ready(function(){
	$("#pswd-show-hide").click(function(){
		if ($("#pwdvisible").attr("type") === "password"){
			$("#pwdvisible").attr("type", "text");
			$(this).toggleClass("icon-eye4 icon-eye3");
		} else{
			$("#pwdvisible").attr("type", "password");
			$(this).toggleClass("icon-eye3 icon-eye4");
		}
	});
	$("#signup-pswd-show-hide").click(function(){
		if ($("#sign-pwdvisible").attr("type") === "password"){
			$("#sign-pwdvisible").attr("type", "text");
			$(this).toggleClass("icon-eye4 icon-eye3");
		} else{
			$("#sign-pwdvisible").attr("type", "password");
			$(this).toggleClass("icon-eye3 icon-eye4");
		}
	});
	$("#signup-pswd-cnf-show-hide").click(function(){
		if ($("#sign-cnfpwdvisible").attr("type") === "password"){
			$("#sign-cnfpwdvisible").attr("type", "text");
			$(this).toggleClass("icon-eye4 icon-eye3");
		} else{
			$("#sign-cnfpwdvisible").attr("type", "password");
			$(this).toggleClass("icon-eye3 icon-eye4");
		}
	});
	$("#forgot-pswd-cnf-show-hide").click(function(){
		if ($("#forgot-cnfpwdvisible").attr("type") === "password"){
			$("#forgot-cnfpwdvisible").attr("type", "text");
			$(this).toggleClass("icon-eye4 icon-eye3");
		} else{
			$("#forgot-cnfpwdvisible").attr("type", "password");
			$(this).toggleClass("icon-eye3 icon-eye4");
		}
	});
});