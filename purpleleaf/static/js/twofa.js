function getCookie(name) {
    var cookieValue = null;
    if (document.cookie && document.cookie != '') {
        var cookies = document.cookie.split(';');
        for (var i = 0; i < cookies.length; i++) {
            var cookie = jQuery.trim(cookies[i]);
            // Does this cookie string begin with the name we want?
            if (cookie.substring(0, name.length + 1) == (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

$.ajaxPrefilter(function(options, originalOptions, jqXHR){
    if (options['type'].toLowerCase() === "post") {
        jqXHR.setRequestHeader('X-CSRFToken', getCookie('csrftoken'));
    }
});



$(document).ready(function () {
    $('#g_auth').validate({ // initialize the plugin
        rules: {
            otp: {
                required: true,
                number: true,
                minlength : 6,
                maxlength: 6
            }
        },
    });
    $('#phone_auth').validate({ // initialize the plugin
        rules: {
            phone: {
                required: true,
                phoneUS: true,
            },
            phone_otp: {
                required: true,
                number: true,
                maxlength: 6,
                minlength: 6
            }
        },
    });
});


$(document).on("submit", "form#phone_auth", function(e){
    e.preventDefault();
    VerifyLoginOtp();
});

function VerifyLoginOtp(){
    var otp = $('#verify_otp_id').val();
    var form_valid = $("#phone_auth").valid();
    if (form_valid){
        $.ajax({
            url: '/verify-2fa/',
            type: 'POST',
            data: {
                'otp': otp
                },
            success: function(response){
                if (response == true){
                    $.growl.notice({title:"Success", message: "OTP verified successfully!" });
                     setTimeout(function() {
                      window.location.href = "/dashboard/";
                    }, 2000);
                }
                else if(response == false){
                    $.growl.error({title:"Error!", message: "Incorrect OTP" });
                }
                else if (response == 'error'){
                   var error_message = "A 2FA error has occured, the support team has been notified"
                   $.growl.error({title:"Error!", message: error_message});
                }
                else{
                    $.growl.error({title:"Error!", message: "An unknown error has occurred" });
                    setTimeout(function() {
                        window.location.href = "/signin/";
                    }, 3000);
                }
           }
       });
    }
}


$(document).on("submit", "form#g_auth", function(e){
    e.preventDefault();
    VerifyLoginTotp();
});



function VerifyLoginTotp(){
    var otp = $('#gauth_otp').val();
    var form_valid = $("#g_auth").valid();
    if (form_valid){
        $.ajax({
        url: '/verify-2fa/',
        type: 'POST',
        data: {
            'totp': otp
            },
            success: function(response){
                if (response == true){
                    $.growl.notice({title:"Success", message: "OTP verified successfully!" });
                    setTimeout(function() {
                        window.location.href = "/dashboard/";
                    }, 2000);
                }
                else if (response == false){
                   var otp = $('#gauth_otp').val('');
                   $.growl.error({title:"Error!", message: "Incorrect OTP" });
                }
                else if (response == 'error'){
                   var otp = $('#gauth_otp').val('');
                   var error_message = "A 2FA error has occured, the support team has been notified"
                   $.growl.error({title:"Error!", message: error_message});
                }
                else{
                    $.growl.error({title:"Error!", message: "An unknown error has occurred" });
                    setTimeout(function() {
                        window.location.href = "/signin/";
                    }, 3000);
                }
           }
        });
    }
}

