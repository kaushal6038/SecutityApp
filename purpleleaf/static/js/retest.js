
	// using jQuery for getting csrf token
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
var csrftoken = getCookie('csrftoken');


function addRetest(id){
	$.ajax({
            url: '/api/retest/' + id,
            type: 'POST',
            data: {},
            success: function(response){
                if (response.status_code == 200){
                    btn = '#btn-retest-' + id;
                    td = '#btn-retest-td-' + id;
                	$(btn).remove()
                	$(td).text('Requested')
                	$.growl.notice(
	                	{
	                		title: "Success",
	                		message: response.message
	                	}
                	);
                }
                else {
                	$.growl.error(
	                	{
	                		title: "Error",
	                		message: "Unable to request retest."
	                	}
                	);
                }
           },
           error: function (xhr, ajaxOptions, thrownError) {
               $.growl.error({title:"Oops!", message: thrownError });
           }
       });
}