import { mountKukuroo } from "./mount.ts";

const kukuroo = mountKukuroo({
  prefix: "",
  standalone: true,
  requireInvite: false,
});

export default {
  async fetch(request: Request, env: any): Promise<Response> {
    const hit = await kukuroo.handle(request, env);
    if (hit !== null) return hit;

    const url = new URL(request.url);
    //直接在cf里面订阅github的时候，要加一个重定向，否则会报错
    if (url.pathname === "/" || url.pathname === "") {
      return Response.redirect(url.origin + "/enroll", 302);
    }
    return new Response("Not found", { status: 404 });
  },
};