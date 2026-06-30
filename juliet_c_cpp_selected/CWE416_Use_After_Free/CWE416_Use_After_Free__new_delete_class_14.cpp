/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE416_Use_After_Free__new_delete_class_14.cpp
Label Definition File: CWE416_Use_After_Free__new_delete.label.xml
Template File: sources-sinks-14.tmpl.cpp
*/
/*
 * @description
 * CWE: 416 Use After Free
 * BadSource:  Allocate data using new, initialize memory block, and Deallocate data using delete
 * GoodSource: Allocate data using new and initialize memory block
 * Sinks:
 *    GoodSink: Do nothing
 *    BadSink : Use data after delete
 * Flow Variant: 14 Control flow: if(globalFive==5) and if(globalFive!=5)
 * */

#include "std_testcase.h"

#include <wchar.h>

namespace CWE416_Use_After_Free__new_delete_class_14
{

#ifndef OMITBAD

void bad()
{
    TwoIntsClass * data;
    /* Initialize data */
    data = NULL;
    if(globalFive==5)
    {
        data = new TwoIntsClass;
        data->intOne = 1;
        data->intTwo = 2;
        /* POTENTIAL FLAW: Delete data in the source - the bad sink attempts to use data */
        delete data;
    }
    if(globalFive==5)
    {
        /* POTENTIAL FLAW: Use of data that may have been deleted */
        printIntLine(data->intOne);
        /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not deleted */
    }
}

#endif /* OMITBAD */


} /* close namespace */

/* Below is the main(). It is only used when building this testcase on
   its own for testing or for building a binary to use in testing binary
   analysis tools. It is not used when compiling all the testcases as one
   application, which is how source code analysis tools are tested. */

#ifdef INCLUDEMAIN

using namespace CWE416_Use_After_Free__new_delete_class_14; /* so that we can use good and bad easily */

int main(int argc, char * argv[])
{
    /* seed randomness */
    srand( (unsigned)time(NULL) );
#ifndef OMITBAD
    printLine("Calling bad()...");
    bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
