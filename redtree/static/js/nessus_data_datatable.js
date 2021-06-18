$(document).ready(function() {
    $('#nessus-data-datatable').DataTable( {
    	// "aaSorting" and "order" are to retain ordering
    	"aaSorting": [],	
    	"order": [],
        "paging":   false,
        "columnDefs": [ {
            "orderable": false,
            "targets": [ 0,1,2,3,4 ]
        },
        { 
            "searchable"    : false, 
            "targets"       : [0,1,3,4] 
        },]
    } );

    // DataTable
    var table = $('#nessus-data-datatable').DataTable();
    // Apply the search
    table.columns(2).every( function () {
        var that = this;

        $( '.datatable_input', this.footer() ).on( 'keyup change', function () {
            if ( that.search() !== this.value ) {
                that
                    .search( this.value )
                    .draw();
            }
        } );
    } );
} );