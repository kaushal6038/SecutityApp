$(document).ready(function(){
    $(".app_image").mouseover(function(){
        var id = $(this).attr('id');
        var app_id = $(this).attr('value');

        var app_title_id = '#app_title_' + app_id;
        var application_title = $(app_title_id).val();
        
        var app_first_seen_id = '#app_first_seen_' + app_id;
        var application_first_seen = $(app_first_seen_id).val();
        
        var app_last_scan_id = '#app_last_scan_' + app_id;
        var application_last_scan = $(app_last_scan_id).val();
        
        var app_last_seen_id = '#app_last_seen_' + app_id;
        var application_last_seen = $(app_last_seen_id).val();
        
        var image_id = '#s3-' + id;

        var image_obj = $(image_id).attr('src');
        console.log("image_obj", image_obj)

        if(!image_obj){
            html_content = "<src='/static/img/screenshot_error.png'>";
            $("#show_and_hide_image").append(html_content);
        }
        else{
            $("#show_and_hide_image").addClass("panel");
            var title_tr = "<p style='border: 1px solid; padding: 4px 4px 4px 4px'>"
                + application_title
                + "</p>"
            var screenshot_tr = "<p><img id='app_screenshot_width' src='"
                + image_obj
                + "'></p>"
            var application_status = null;
            var application_status_tr = null
            if (application_first_seen != 'None'){
                application_status = "<b>First seen:</b>&nbsp;&nbsp;&nbsp;"
                    + application_first_seen
                    + "<br>"
            }
            if (application_last_seen != 'None'){
                application_status = application_status
                    + "<b>Last seen:</b>&nbsp;&nbsp;&nbsp;"
                    + application_last_seen
                    + "<br>"
            }
            if (application_last_scan != 'None'){
                application_status = application_status
                    + "<b>Last scan:</b>&nbsp;&nbsp;&nbsp;"
                    + application_last_scan
            }
            if (application_status){
                application_status_tr = "<p style='border: 1px solid; padding: 8px 6px 8px 6px'>"
                    + application_status
                    + "</p>"
            }

            if (application_status_tr){
                html_content = title_tr + screenshot_tr + application_status_tr
            }
            else{
                html_content = title_tr + screenshot_tr
            }
            $("#show_and_hide_image").append(html_content);
        }
    });
    $(".app_image").mouseout(function(){
        $("#show_and_hide_image").removeClass("panel");
        $("#show_and_hide_image").html("<img src=''/>");
    });
});

function update_app_status(obj){
    var app_id = obj.id;
    var application_id = app_id.substr(4)
    var scan_status =obj.value;
    $.ajax({
        type: "POST",
        url: application_id + "/toggle_active/",
        data: {
            'scan_status' : scan_status
        },
        dataType: 'json',
        success: function(response) {
            if (response.status == true){
                $.growl.notice(
                    {
                        title:"Success",
                        message: response.message
                    }
                );
                var app_text_id = "#app_scan_status_" + application_id;
                var app_button_id = "#app_" + application_id;
                if (response.data.scanning_enabled){
                    var app_font_class = "btn btn-success btn-transparent btn-xs sucess_active_button";
                }
                else{
                    var app_font_class = "btn btn-danger btn-transparent btn-xs";
                }
                $(app_text_id).text(response.data.scan_status);
                $(app_button_id).val(response.data.scan_status);
                $(app_button_id).attr('class', app_font_class);
            }
            else if (response.status == false){
                if (response.status_code == 400){
                    $.growl.error(
                        {
                            title: response.message,
                            message: response.errors.non_field_errors
                        }
                    );
                }
                else{
                    $.growl.error(
                        {
                            title: "Error " + response.status_code,
                            message: response.message
                        }
                    );
                }
            }
            else {
                $.growl.error({title:"Error!", message: "Unable to update application scan status" });
            }
        }
    });

}


function burp_app_status(obj){
    var app_id = obj.id;
    var application_id = app_id.substr(4)
    var scan_status =obj.value;
    $.ajax({
        type: "POST",
        url: application_id + "/burp_toggle_active/",
        data: {
            'scan_status' : scan_status
        },
        dataType: 'json',
        success: function(response) {
            if (response.status == true){
                $.growl.notice(
                    {
                        title:"Success",
                        message: response.message
                    }
                );
                var app_text_id = "#app_scan_status_" + application_id;
                var app_button_id = "#app_" + application_id;
                if (response.data.scanning_enabled){
                    var app_font_class = "btn btn-success btn-transparent btn-xs sucess_active_button";
                }
                else{
                    var app_font_class = "btn btn-danger btn-transparent btn-xs";
                }
                $(app_text_id).text(response.data.scan_status);
                $(app_button_id).val(response.data.scan_status);
                $(app_button_id).attr('class', app_font_class);
            }
            else if (response.status == false){
                if (response.status_code == 400){
                    $.growl.error(
                        {
                            title: response.message,
                            message: response.errors.non_field_errors
                        }
                    );
                }
                else{
                    $.growl.error(
                        {
                            title: "Error " + response.status_code,
                            message: response.message
                        }
                    );
                }
            }
            else {
                $.growl.error({title:"Error!", message: "Unable to update application scan status" });
            }
        }
    });

}

function open_application_title(obj){
    var application_id = obj.id;
    // var application_title = obj.value;
    $('#edit_application_title_id').val(application_id);
    // $('#edit_application_title_value').val(application_title);
    $.ajax({
        type:'GET',
        url: "/application/edit-title/"+application_id+'/',
        cache:false,
        contentType: false,
        processData: false,
        success:function(response){
            console.log(response)
            $('.application-modal-body').html(response);
            $('#applicationTitleModal').modal('show');
        }
    })
}

$('#editApplicationTitleForm').submit(function(e) {
    e.preventDefault();
    var id = $('#edit_application_title_id').val();
    var formData = new FormData(this);
    $.ajax({
        type:'POST',
        url: "/application/edit-title/"+id+'/',
        data:formData,
        cache:false,
        contentType: false,
        processData: false,
        success:function(response){
            if (response.status == true){
                $.growl.notice(
                    {
                        title:"Success",
                        message: response.message
                    }
                );
                location.reload();
            }
            else if (response.status == false){
                $.growl.error(
                    {
                        title: "Error " + response.status_code,
                        message: response.message
                    }
                );
            }
            else {
                $.growl.error({title:"Error!", message: "Unable to update application title" });
            }
        }
    });
});

function updateApplicationScope(obj){
    var application_id = obj.id;
    var app_id = application_id.substr(18);
    var application_scope = obj.value;
    $.ajax({
        type: "POST",
        url: "/application/toggle-scope/"+app_id+"/",
        data: {
            'application_scope' : application_scope
        },
        dataType: 'json',
        success: function(response) {
            if (response.status == true){
                $.growl.notice(
                    {
                        title:"Success",
                        message: response.message
                    }
                );
                var app_id = response.data.application_id;
                var app_scope = response.data.application_scope;
                var app_button_id = "#application_scope_" + app_id;
                if (app_scope == "black"){
                    var button_text = "Black Box";
                }else{
                    var button_text = "Gray Box";
                }
                $(app_button_id).text(button_text);
                $(app_button_id).val(app_scope);
                $(app_button_id).toggleClass('black_scope_button gray_scope_button');
            }
            else if (response.status == false){
                $.growl.error(
                    {
                        title: "Error " + response.status_code,
                        message: response.message
                    }
                );
            }
            else {
                $.growl.error({title:"Error!", message: "Unable to update application title" });
            }
        }
    });
}
