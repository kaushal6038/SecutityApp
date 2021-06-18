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
    $('#verify_otp').validate({ // initialize the plugin
        rules: {
            otp: {
                required: true,
                number: true,
                minlength : 6,
                maxlength: 6
            }
        },
    });
});

$(document).on("submit", "form#g_auth", function(e){
    e.preventDefault();
    VerifyTotp();
});

$(document).on("submit", "form#phone_auth", function(e){
    e.preventDefault();
    GenerateOtp();
});

$(document).on("submit", "form#verify_otp", function(e){
    e.preventDefault();
    VerifyOtp();
});

function GenerateOtp(){
    var phone_number = $('#generate_otp_id').val();
    var form_valid = $("#phone_auth").valid();
    if (form_valid){
        $(".verification-number-btn").button('loading');
        $(".verification-number-btn").attr("disabled", true);
        $.ajax({
            url: 'generate-otp/',
            type: 'POST',
            data: {
                'phone_number': phone_number
                },
            success: function(response){
                if (response.status == true){
                    $('.verification-number-dsn').val("");
                    $('.verification-number-dsn').attr("placeholder", "Enter OTP");
                    $('.verification-number-dsn').attr("id", "verify_otp_id");
                    $('.verification-number-dsn').attr("name", "phone_otp");
                    $('.phone-h5').text("Enter OTP received:");
                    $(".verification-number-btn").attr("disabled", false);
                    $('.verification-number-btn').attr("onclick", "VerifyOtp()");
                    $('#phone_auth').prop("id", "verify_otp");
                    $('.verification-number-btn').text("Verify");
                }

                else if (response.status == false && response.message != null){
                    $(".verification-number-btn").button('reset');
                    $(".verification-number-btn").attr("disabled", false);
                    $.growl.error({title:"Error!", message: response.message });

                }

                else{
                    $(".verification-number-btn").button('reset');
                    $(".verification-number-btn").attr("disabled", false);
                    $.growl.error({title:"Error!", message: "Unable to Generate OTP. Please Try again later or reconfirm number" });
                }
           }
       });

    }
}


function VerifyOtp(){
    var otp = $('#verify_otp_id').val();
    var form_valid = $("#verify_otp").valid();
    if (form_valid){
        $.ajax({
            url: 'sms/otp/',
            type: 'POST',
            data: {
                'otp': otp
                },
            success: function(response){
                console.log('response',response)
                if (response == true){
                    $.growl.notice({title:"Success", message: "OTP verified successfully!" });
                     setTimeout(function() {
                      window.location.href = "/signin/";
                    }, 500);
                }
                else if(response == false){
                    $.growl.error({title:"Error!", message: "Incorrect OTP" });
                }
                else{
                    $.growl.error({title:"Error!", message: "Unable to generate OTP" });
                }
           }
       });
    }
}


function VerifyTotp(){
    var otp = $('#gauth_otp').val();
    var form_valid = $("#g_auth").valid();
    if (form_valid){
        $.ajax({
        url: 'google-auth/otp/',
        type: 'POST',
        data: {
            'otp': otp
            },
            success: function(response){
                if (response == true){
                     $.growl.notice({title:"Success", message: "OTP verified successfully!" });
                     setTimeout(function() {
                      window.location.href = "/signin/";
                    }, 500);
                }
                else if (response == false){
                   var otp = $('#gauth_otp').val('');
                   $.growl.error({title:"Error!", message: "Incorrect OTP" });
                }
                else{
                    setTimeout(function() {
                      window.location.href = "/error404/";
                    }, 500);
                }
           }
        });
    }

}










