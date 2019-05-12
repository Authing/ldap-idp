declare const ldap: any;
declare function authorize(req: {
    connection: {
        ldap: {
            bindDN: {
                equals: (arg0: string) => string;
            };
        };
    };
}, _res: any, next: {
    (arg0: any): void;
    (): void;
}): void;
declare var SUFFIX: string;
declare var db: any;
declare var server: any;
