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
});